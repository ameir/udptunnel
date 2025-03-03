// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"context"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-reuseport"
	tun "github.com/sina-ghaderi/tunnel"
)

type direction byte

const (
	outbound direction = 'T' // Transmit
	inbound  direction = 'R' // Receive
)

type logger interface {
	Fatalf(string, ...interface{})
	Printf(string, ...interface{})
}

type tunnel struct {
	server        bool
	tunDevName    string
	tunLocalAddr  string
	tunRemoteAddr string
	netAddr       string
	beatInterval  time.Duration

	log logger

	// remoteAddr is the address of the remote endpoint and may be
	// arbitrarily updated.
	remoteAddr atomic.Value
}

// run starts the VPN tunnel over UDP using the provided config and logger.
// When the context is canceled, the function is guaranteed to block until
// it is fully shutdown.
//
// The channels testReady and testDrop are only used for testing and may be nil.
func (t tunnel) run(ctx context.Context) {
	// Determine the daemon mode from the network address.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Create a new tunnel device (requires root privileges).

	iface, err := tun.New(tun.Config{Name: "ut0", DisableGsoGro: true})
	if err != nil {
		t.log.Fatalf("error creating tun device: %v", err)
	}
	t.log.Printf("created tun device: %v", iface.Name())
	defer iface.Close()

	// Setup IP properties.
	switch runtime.GOOS {
	case "linux":
		if err := exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", "1400").Run(); err != nil {
			t.log.Fatalf("ip link error: %v", err)
		}
		if err := exec.Command("ip", "addr", "add", t.tunLocalAddr+"/24", "dev", iface.Name()).Run(); err != nil {
			t.log.Fatalf("ip addr error: %v", err)
		}
		if err := exec.Command("ip", "link", "set", "dev", iface.Name(), "up").Run(); err != nil {
			t.log.Fatalf("ip link error: %v", err)
		}
	case "darwin":
		if err := exec.Command("ifconfig", iface.Name(), "mtu", "1300", t.tunLocalAddr, t.tunRemoteAddr, "up").Run(); err != nil {
			t.log.Fatalf("ifconfig error: %v", err)
		}
	default:
		t.log.Fatalf("no tun support for: %v", runtime.GOOS)
	}

	// Create a new UDP socket.
	_, port, _ := net.SplitHostPort(t.netAddr)
	laddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("", port))
	if err != nil {
		t.log.Fatalf("error resolving address: %v", err)
	}
	//sock, err := net.ListenUDP("udp4", laddr)
	lp, err := reuseport.ListenPacket("udp4", laddr.String())
	if err != nil {
		t.log.Fatalf("error listening on socket: %v", err)
	}
	defer lp.Close()
	sock := lp.(*net.UDPConn)

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435
	pf := newPortFilter()

	// On the client, start some goroutines to accommodate for the dynamically
	// changing environment that the client may be in.
	if !t.server {
		// Since the remote address could change due to updates to DNS,
		// periodically check DNS for a new address.
		raddr, err := net.ResolveUDPAddr("udp4", t.netAddr)
		if err != nil {
			t.log.Fatalf("error resolving address: %v", err)
		}
		t.updateRemoteAddr(raddr)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				raddr, _ := net.ResolveUDPAddr("udp4", t.netAddr)
				if isDone(ctx) {
					return
				}
				t.updateRemoteAddr(raddr)
			}
		}()

		// Since the local address could change due to switching interfaces
		// (e.g., switching from cellular hotspot to hardwire ethernet),
		// periodically ping the server to inform it of our new UDP address.
		// Sending a packet with only the magic header is sufficient.
		go func() {
			if t.beatInterval == 0 {
				return
			}
			ticker := time.NewTicker(t.beatInterval)
			defer ticker.Stop()
			for range ticker.C {
				if isDone(ctx) { // Stop if done.
					return
				}
				raddr := t.loadRemoteAddr()
				if raddr == nil { // Skip if no remote endpoint.
					continue
				}
			}
		}()
	}

	// Handle outbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		//var unwritten []byte
		for {
			n, err := iface.Read(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Fatalf("tun read error: %v", err)
			}

			raddr := t.loadRemoteAddr()
			if pf.Filter(b[:n]) || raddr == nil {
				continue
			}

			n2, err := sock.WriteToUDP(b[:n], raddr)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net write error: %v\n", err)

				time.Sleep(time.Second)
				continue
			}
			if n != n2 {
				t.log.Printf("payload size: %d, written size: %d\n\n", n, n2)

			}

		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		var unwritten []byte
		for {
			nr, raddr, err := sock.ReadFromUDP(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net read error: %v", err)
				time.Sleep(time.Second)
				continue
			}

			// We assume a matching magic prefix is sufficient to validate
			// that the new IP is really the remote endpoint.
			// We assume that any adversary capable of performing a replay
			// attack already has the power to disrupt communication.
			if t.server {
				t.updateRemoteAddr(raddr)
			}

			if nr == 0 {
				continue // Assume empty packets are a form of pinging
			}

			x := append(unwritten, b[:nr]...)

			if pf.Filter(x) {
				continue
			}

			nw, err := iface.Write(x)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("tun write error: %v", err)
			}

			if nr > nw {
				offset := nr - nw
				t.log.Printf("need to write %d more bytes", offset)
				unwritten = x[offset:]
			} else {
				unwritten = nil
			}

		}
	}()

	<-ctx.Done()
}

func (t *tunnel) loadRemoteAddr() *net.UDPAddr {
	addr, _ := t.remoteAddr.Load().(*net.UDPAddr)
	return addr
}
func (t *tunnel) updateRemoteAddr(addr *net.UDPAddr) {
	oldAddr := t.loadRemoteAddr()
	if addr != nil && (oldAddr == nil || !addr.IP.Equal(oldAddr.IP) || addr.Port != oldAddr.Port || addr.Zone != oldAddr.Zone) {
		t.remoteAddr.Store(addr)
		t.log.Printf("switching remote address: %v", addr)
	}
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
