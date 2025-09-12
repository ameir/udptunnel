// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-reuseport"
	tun "github.com/sina-ghaderi/tunnel"
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

	// For client mode: the resolved UDP address of the server.
	serverUDPAddr atomic.Value // Stores *net.UDPAddr of the server

	// For server mode:
	activeClients    *sync.Map // Key: client public UDP Addr (string). Value: *clientSession
	tunnelIPtoClient *sync.Map // Key: client tunnel IP (string). Value: *net.UDPAddr (client public UDP Addr)
}

type clientSession struct {
	publicAddr *net.UDPAddr
	tunnelIP   string // Client's private/tunnel IP, learned from its first data packet
	lastActive time.Time
}

// serverClientStaleTimeout defines how long before an inactive client session is removed by the server.
const serverClientStaleTimeout = 90 * time.Second
const pingPrefix = "ping|"

// ipPacket is an IP packet. The slice is the packet data.

// run starts the VPN tunnel over UDP using the provided config and logger.
// When the context is canceled, the function is guaranteed to block until
// it is fully shutdown.
//
// The channels testReady and testDrop are only used for testing and may be nil.
func (t tunnel) run(ctx context.Context) {
	// Determine the daemon mode from the network address.
	var wg sync.WaitGroup
	defer wg.Wait()

	if t.server {
		t.activeClients = &sync.Map{}
		t.tunnelIPtoClient = &sync.Map{}
		go t.cleanupStaleClients(ctx, serverClientStaleTimeout)
	}

	// Create a new tunnel device (requires root privileges).
	tunCfg := tun.Config{Name: t.tunDevName, DisableGsoGro: true}
	iface, err := tun.New(tunCfg)
	if err != nil {
		t.log.Fatalf("error creating tun device: %v", err)
	}
	t.log.Printf("created tun device: %v", iface.Name())
	defer iface.Close()

	// Setup IP properties.
	switch runtime.GOOS {
	case "linux":
		if err := exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", "1420").Run(); err != nil {
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
		// This single goroutine handles all periodic client-side tasks:
		// 1. Resolves the server's DNS address to handle dynamic IP changes.
		// 2. Sends periodic heartbeats (if configured) to maintain NAT state.
		go func() {
			// Use the configured heartbeat interval, or a 30s default for DNS-only checks.
			if t.beatInterval == 0 {
				t.beatInterval = 30 * time.Second
				t.log.Printf("setting default heartbeat interval: %d", t.beatInterval)
			}

			// Define the task to be run periodically.
			task := func() {
				raddr, err := net.ResolveUDPAddr("udp4", t.netAddr)
				if err != nil {
					t.log.Printf("error resolving server address: %v", err)
					return
				}
				t.updateServerUDPAddr(raddr)

				// If heartbeats are enabled, send one to the latest address.
				if raddr != nil {
					if _, err := sock.WriteToUDP(fmt.Append(nil, pingPrefix, t.tunLocalAddr), raddr); err != nil && !isDone(ctx) {
						t.log.Printf("client heartbeat send error: %v", err)
					}
					t.log.Printf("sent client heartbeat: %v", raddr)
				}
			}

			task() // Run once immediately.

			ticker := time.NewTicker(t.beatInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					task()
				}
			}
		}()
	}

	// Handle outbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16)
		var parsedServerLocalTunIP net.IP
		if t.server {
			parsedServerLocalTunIP = net.ParseIP(t.tunLocalAddr)
			if parsedServerLocalTunIP == nil {
				t.log.Fatalf("failed to parse server's local tunnel IP: %s", t.tunLocalAddr)
			}
		}
		for {
			n, err := iface.Read(b)
			if err != nil {
				if isDone(ctx) {
					return
				}
				// Log non-fatal TUN read errors and attempt to continue.
				// Certain errors might indicate the TUN device is closed, warranting goroutine exit.
				t.log.Printf("tun read error: %v; attempting to continue", err)
				if err.Error() == "read /dev/net/tun: file already closed" || err.Error() == "read /dev/utun: file already closed" { // Example check
					t.log.Printf("TUN device appears closed, exiting read goroutine: %v", err)
					return
				}
				time.Sleep(time.Second)
				continue
			}

			ipPacketPayload := b[:n]

			if t.server {
				// Server mode: determine destination client from IP packet's destination
				ipPkt := ipPacket(ipPacketPayload) // Use the ipPacket type from filter.go

				_, dstTunIP := ipPkt.AddressesV4NetIP() // Get net.IP
				//	t.log.Printf("dstTunIP: %s\n", dstTunIP.String())
				if dstTunIP == nil {
					t.log.Printf("Could not determine destination tunnel IP from TUN packet. Dropping.")
					continue
				}

				// Avoid sending packets to self if server's TUN IP is the destination
				if dstTunIP.Equal(parsedServerLocalTunIP) {
					t.log.Printf("Dropping packet from TUN destined for server's own tunnel IP: %s", dstTunIP.String())
					continue
				}

				raddrInterface, ok := t.tunnelIPtoClient.Load(dstTunIP.String())
				//	t.log.Printf("raddrInterface: %s\n", raddrInterface)
				if !ok {
					t.log.Printf("No known public UDP address for tunnel IP %s. Dropping packet.", dstTunIP.String())
					continue
				}
				raddr := raddrInterface.(*net.UDPAddr)

				if pf.Filter(ipPacketPayload) {
					t.log.Printf("Outbound packet to %s (tunnel %s) dropped by filter", raddr.String(), dstTunIP.String())
					continue
				}
				_, err = sock.WriteToUDP(ipPacketPayload, raddr)
			} else { // Client mode
				raddr := t.loadServerUDPAddr()
				if raddr == nil {
					continue // No server address known
				}
				if pf.Filter(ipPacketPayload) {
					t.log.Printf("Outbound packet to server %s dropped by filter", raddr.String())
					continue
				}
				_, err = sock.WriteToUDP(ipPacketPayload, raddr)
			}

			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net write error: %v", err)
				time.Sleep(time.Second) // Back off on write error
			}
		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 1<<16) // Buffer for ReadFromUDP
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

			ipPayload := b[:nr]

			if t.server {

				ipPkt := ipPacket(ipPayload) // Use ipPacket type from filter.go

				if ipPkt.Version() != 4 {

					// check if heartbeat
					if strings.HasPrefix(string(ipPayload), pingPrefix) { // Heartbeat from client
						clientTunIp := strings.TrimPrefix(string(ipPayload), pingPrefix)

						var session *clientSession
						sessionInterface, _ := t.activeClients.LoadOrStore(raddr.String(), &clientSession{
							publicAddr: raddr,
							lastActive: time.Now(),
						})
						session = sessionInterface.(*clientSession)
						session.lastActive = time.Now()

						if session.tunnelIP == "" { // only need to register IP first time since it shouldn't change
							if raddrInterface, ok := t.tunnelIPtoClient.Load(clientTunIp); ok {
								t.log.Printf("Client %s changed public IP from %s to %s", clientTunIp, raddrInterface.(*net.UDPAddr).String(), raddr.String())
							}
							session.tunnelIP = clientTunIp
							t.tunnelIPtoClient.Store(clientTunIp, raddr)
							t.log.Printf("Updated tunnel IP for %s to %s", raddr.String(), clientTunIp)
						}
						t.log.Printf("Received heartbeat from client %s (%s)", raddr.String(), session.tunnelIP)

						continue // Processed heartbeat
					} else {
						t.log.Printf("Received non-IPv4 data packet from %s. Dropping.", raddr.String())
						continue
					}
				}

			} else { // Client mode
				if len(ipPayload) == 0 {
					t.log.Printf("Client received heartbeat from server %s", raddr.String())
					continue // Processed heartbeat
				}
			}

			if pf.Filter(ipPayload) {
				// Log which client's packet was filtered if in server mode
				// Additional logging can be added here if desired.
				continue
			}

			nw, err := iface.Write(ipPayload)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("tun write error: %v", err)
			}

			if nr > nw {
				offset := nr - nw
				t.log.Printf("need to write %d more bytes", offset)
			}
		}
	}()

	<-ctx.Done()
}

func (t *tunnel) loadServerUDPAddr() *net.UDPAddr {
	if t.server {
		return nil // Server doesn't have one single "remote"
	}
	addr, _ := t.serverUDPAddr.Load().(*net.UDPAddr)
	return addr
}

func (t *tunnel) updateServerUDPAddr(addr *net.UDPAddr) {
	if t.server {
		return // Server doesn't use this
	}
	oldAddr, _ := t.serverUDPAddr.Load().(*net.UDPAddr)
	if addr != nil && (oldAddr == nil || !addr.IP.Equal(oldAddr.IP) || addr.Port != oldAddr.Port || addr.Zone != oldAddr.Zone) {
		t.serverUDPAddr.Store(addr)
		t.log.Printf("switching remote server address: %v", addr)
	}
}

func (t *tunnel) cleanupStaleClients(ctx context.Context, staleTimeout time.Duration) {
	if staleTimeout == 0 {
		staleTimeout = serverClientStaleTimeout
	}
	ticker := time.NewTicker(staleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			t.activeClients.Range(func(key interface{}, value interface{}) bool {
				session := value.(*clientSession)
				if now.Sub(session.lastActive) > staleTimeout {
					clientAddrStr := key.(string)
					t.log.Printf("Removing stale client session: %s (Tunnel IP: %s)", clientAddrStr, session.tunnelIP)
					t.activeClients.Delete(key)

					// if a client's public IP changes, don't delete the tunnelIPtoClient mapping
					if raddrInterface, ok := t.tunnelIPtoClient.Load(session.tunnelIP); ok {
						raddr := raddrInterface.(*net.UDPAddr)
						if clientAddrStr == raddr.String() {
							t.tunnelIPtoClient.Delete(session.tunnelIP)
						} else {
							t.log.Printf("Public IP for tunnel IP %s changed from %s to %s", session.tunnelIP, clientAddrStr, raddr.String())
						}
					}
				}
				return true // Continue iteration
			})
		}
	}
}

func isDone(ctx context.Context) bool {
	return ctx.Err() != nil
}
