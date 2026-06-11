// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
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
	disableGsoGro bool

	log logger

	// For client mode: the resolved UDP address of the server.
	serverUDPAddr atomic.Value // Stores *net.UDPAddr of the server

	// For server mode:
	activeClients    *sync.Map // Key: client public UDP Addr (string). Value: *clientSession
	tunnelIPtoClient *sync.Map // Key: client tunnel IP (string). Value: *net.UDPAddr (client public UDP Addr)
}

type clientSession struct {
	mu         sync.Mutex
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
	tunCfg := tun.Config{Name: t.tunDevName, DisableGsoGro: t.disableGsoGro}
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
	if !t.server {
		port = "0"
	}
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
	if err := sock.SetReadBuffer(4 << 20); err != nil {
		t.log.Printf("failed to set read buffer size: %v", err)
	}
	if err := sock.SetWriteBuffer(4 << 20); err != nil {
		t.log.Printf("failed to set write buffer size: %v", err)
	}

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435
	pf := newPortFilter()

	// On the client, start some goroutines to accommodate for the dynamically
	// changing environment that the client may be in.
	if !t.server {
		// Pre-allocate heartbeat message (tunLocalAddr never changes).
		heartbeatMsg := []byte(pingPrefix + t.tunLocalAddr)

		// Use the configured heartbeat interval, or a 30s default for DNS-only checks.
		beatInterval := t.beatInterval
		if beatInterval == 0 {
			beatInterval = 30 * time.Second
		}

		// This single goroutine handles all periodic client-side tasks:
		// 1. Resolves the server's DNS address to handle dynamic IP changes.
		// 2. Sends periodic heartbeats (if configured) to maintain NAT state.
		go func() {
			// Define the task to be run periodically.
			task := func() {
				raddr, err := net.ResolveUDPAddr("udp4", t.netAddr)
				if err != nil {
					t.log.Printf("error resolving server address: %v", err)
					return
				}
				t.updateServerUDPAddr(raddr)

				if _, err := sock.WriteToUDPAddrPort(heartbeatMsg, raddr.AddrPort()); err != nil && !isDone(ctx) {
					t.log.Printf("client heartbeat send error: %v", err)
				}
				t.log.Printf("sent client heartbeat: %v", raddr)
			}

			task() // Run once immediately.

			ticker := time.NewTicker(beatInterval)
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
		var parsedServerLocalTunIP net.IP

		if t.server {
			parsedServerLocalTunIP = net.ParseIP(t.tunLocalAddr)
			if parsedServerLocalTunIP == nil {
				t.log.Fatalf("failed to parse server's local tunnel IP: %s", t.tunLocalAddr)
			}
		}

		buffer := make([]byte, 1<<18)
		var overflow []byte
		for {
			n, err := iface.Read(buffer)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("tun read error: %v; attempting to continue", err)
				if errors.Is(err, os.ErrClosed) {
					t.log.Printf("TUN device appears closed, exiting read goroutine: %v", err)
					return
				}
				time.Sleep(time.Second)
				continue
			}

			data := buffer[:n]
			if len(overflow) > 0 {
				data = append(overflow, data...)
				overflow = nil
			}

			for len(data) > 0 {
				if len(data) < 20 || data[0]>>4 != 4 {
					break
				}
				totalLen := int(binary.BigEndian.Uint16(data[2:4]))
				if totalLen < 20 || totalLen > len(data) {
					break
				}
				pkt := data[:totalLen]
				data = data[totalLen:]

				var raddr *net.UDPAddr
				if t.server {
					proto := pkt[9]
					if proto != tcp && proto != udp && proto != icmp {
						continue
					}
					dstTunIP := net.IP(pkt[16:20])
					if dstTunIP.Equal(parsedServerLocalTunIP) {
						continue
					}
					raddrInterface, ok := t.tunnelIPtoClient.Load(dstTunIP.String())
					if !ok {
						continue
					}
					raddr = raddrInterface.(*net.UDPAddr)
				} else {
					proto := pkt[9]
					if proto != tcp && proto != udp && proto != icmp {
						continue
					}
					raddr = t.loadServerUDPAddr()
					if raddr == nil {
						continue
					}
				}

				if _, err := sock.WriteToUDPAddrPort(pkt, raddr.AddrPort()); err != nil {
					if !isDone(ctx) {
						t.log.Printf("net write error: %v", err)
						time.Sleep(time.Second)
					}
					overflow = make([]byte, len(data))
					copy(overflow, data)
					break
				}
			}
		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 1<<18)
		var overflow []byte
		for {
			nr, raddr, err := sock.ReadFromUDPAddrPort(buffer)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("net read error: %v", err)
				time.Sleep(time.Second)
				continue
			}

			ipPayload := buffer[:nr]

			if t.server {
				ipPkt := ipPacket(ipPayload)
				raddrStr := raddr.String()

				if ipPkt.Version() != 4 {
					if strings.HasPrefix(string(ipPayload), pingPrefix) {
						clientTunIp := strings.TrimPrefix(string(ipPayload), pingPrefix)

						var session *clientSession
						sessionInterface, _ := t.activeClients.LoadOrStore(raddrStr, &clientSession{
							publicAddr: net.UDPAddrFromAddrPort(raddr),
							lastActive: time.Now(),
						})
						session = sessionInterface.(*clientSession)

						session.mu.Lock()
						session.lastActive = time.Now()

						needUpdate := false
						if _, ok := t.tunnelIPtoClient.Load(clientTunIp); !ok || session.tunnelIP == "" {
							needUpdate = true
							if session.tunnelIP != "" && session.tunnelIP != clientTunIp {
								t.tunnelIPtoClient.Delete(session.tunnelIP)
							}
							session.tunnelIP = clientTunIp
						}
						session.mu.Unlock()

						if needUpdate {
							t.tunnelIPtoClient.Store(clientTunIp, net.UDPAddrFromAddrPort(raddr))
							t.log.Printf("Updated tunnel IP for %s to %s", raddrStr, clientTunIp)
						}
						continue
					} else {
						t.log.Printf("Received non-IPv4 data packet from %s. Dropping.", raddrStr)
						continue
					}
				}
			}

			if pf.Filter(ipPayload) {
				continue
			}

			if len(overflow) > 0 {
				ipPayload = append(overflow, ipPayload...)
				overflow = nil
			}

			nw, err := iface.Write(ipPayload)
			if err != nil {
				if isDone(ctx) {
					return
				}
				t.log.Printf("tun write error: %v", err)
			}

			if len(ipPayload) > nw {
				offset := len(ipPayload) - nw
				overflow = make([]byte, len(ipPayload)-nw)
				copy(overflow, ipPayload[nw:])
				t.log.Printf("need to write %d more bytes (inbound)", offset)
			} else {
				overflow = nil
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
				session.mu.Lock()
				if now.Sub(session.lastActive) > staleTimeout {
					clientAddrStr := key.(string)
					tunnelIP := session.tunnelIP
					session.mu.Unlock()
					t.log.Printf("Removing stale client session: %s (Tunnel IP: %s)", clientAddrStr, tunnelIP)
					t.activeClients.Delete(key)

					// if a client's public IP changes, don't delete the tunnelIPtoClient mapping
					if raddrInterface, ok := t.tunnelIPtoClient.Load(tunnelIP); ok {
						raddr := raddrInterface.(*net.UDPAddr)
						if clientAddrStr == raddr.String() {
							t.tunnelIPtoClient.Delete(tunnelIP)
						} else {
							t.log.Printf("Public IP for tunnel IP %s changed from %s to %s", tunnelIP, clientAddrStr, raddr.String())
						}
					}
				} else {
					session.mu.Unlock()
				}
				return true // Continue iteration
			})
		}
	}
}

func isDone(ctx context.Context) bool {
	return ctx.Err() != nil
}
