// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
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
	netAddr       string
	beatInterval  time.Duration
	disableGsoGro bool

	log logger

	// serverUDPAddr is atomically swapped by the heartbeat/DNS goroutine and
	// read by the outbound forwarding goroutine in client mode.
	serverUDPAddr atomic.Value // Stores *net.UDPAddr

	// For server mode:
	activeClients    *sync.Map // Key: client public UDP Addr (string). Value: *clientSession
	tunnelIPtoClient *sync.Map // Key: client tunnel IP (string). Value: *net.UDPAddr (client public UDP Addr)
}

type clientSession struct {
	mu         sync.Mutex
	tunnelIP   string // Client's private/tunnel IP, learned from its heartbeat
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
	var wg sync.WaitGroup
	defer wg.Wait()

	if t.server {
		// Server mode learns clients from heartbeats and routes outbound TUN
		// packets by destination tunnel IP.
		t.activeClients = &sync.Map{}
		t.tunnelIPtoClient = &sync.Map{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			t.cleanupStaleClients(ctx, serverClientStaleTimeout)
		}()
		go func() {
			defer wg.Done()
			t.logConnectedClients(ctx, 10*time.Minute)
		}()
	}

	// Create a new tunnel device (requires root privileges).
	tunCfg := tun.Config{Name: t.tunDevName, DisableGsoGro: t.disableGsoGro}
	iface, err := tun.New(tunCfg)
	if err != nil {
		t.log.Fatalf("error creating tun device: %v", err)
	}
	t.log.Printf("created tun device: %v", iface.Name())
	defer iface.Close()

	// Setup Linux IP properties. The MTU leaves room for the outer UDP/IP
	// headers so tunneled packets usually avoid fragmentation.
	if err := exec.Command("ip", "link", "set", "dev", iface.Name(), "mtu", "1420").Run(); err != nil {
		t.log.Fatalf("ip link error: %v", err)
	}
	if err := exec.Command("ip", "addr", "add", t.tunLocalAddr+"/24", "dev", iface.Name()).Run(); err != nil {
		t.log.Fatalf("ip addr error: %v", err)
	}
	if err := exec.Command("ip", "link", "set", "dev", iface.Name(), "up").Run(); err != nil {
		t.log.Fatalf("ip link error: %v", err)
	}

	// Create a new UDP socket.
	_, port, _ := net.SplitHostPort(t.netAddr)
	if !t.server {
		// Clients should not require the same local port as the server; the
		// server learns the client's public address from heartbeats.
		port = "0"
	}
	laddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("", port))
	if err != nil {
		t.log.Fatalf("error resolving address: %v", err)
	}
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
	udpSender := newUDPBatchSender(sock)
	udpReceiver := newUDPBatchReceiver(sock)

	// TODO(dsnet): We should drop root privileges at this point since the
	// TUN device and UDP socket have been set up. However, there is no good
	// support for doing so currently: https://golang.org/issue/1435
	protocolFilter := newProtocolFilter()

	// On the client, start some goroutines to accommodate for the dynamically
	// changing environment that the client may be in.
	if !t.server {
		// Pre-allocate heartbeat message (tunLocalAddr never changes).
		heartbeatMsg := []byte(pingPrefix + t.tunLocalAddr)

		// Keep this goroutine separate from forwarding so DNS changes and NAT
		// refreshes happen even when no tunnel payload is flowing.
		beatInterval := t.beatInterval
		if beatInterval == 0 {
			beatInterval = 30 * time.Second
		}

		// Resolve the server address once synchronously before the outbound
		// forwarder starts. Otherwise the very first packets would be dropped
		// because serverUDPAddr is still nil until the heartbeat goroutine runs.
		if raddr, err := net.ResolveUDPAddr("udp4", t.netAddr); err != nil {
			t.log.Printf("error resolving server address: %v", err)
		} else {
			t.updateServerUDPAddr(raddr)
		}

		// This single goroutine handles all periodic client-side tasks:
		// 1. Resolves the server's DNS address to handle dynamic IP changes.
		// 2. Sends periodic heartbeats (if configured) to maintain NAT state.
		go func() {
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
		batch := make([]udpPacket, 0, maxUDPSendBatch)

		// Flush after each TUN read; WriteBatch chunks internally, so this
		// reduces socket syscalls without waiting to fill a batch.
		flushBatch := func() (int, error) {
			if len(batch) == 0 {
				return 0, nil
			}
			return udpSender.WriteBatch(batch)
		}

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
				// The GSO/GRO-aware TUN library may return multiple IP packets in
				// one read. Keep any incomplete tail and prepend it to the next read.
				data = append(overflow, data...)
				overflow = nil
			}

			for len(data) > 0 {
				if len(data) < 20 {
					// TUN reads are packet-oriented; a tiny tail after parsing one or
					// more complete IPv4 packets is not useful to retry and can be
					// safely ignored.
					t.log.Printf("ignoring short outbound packet tail: remaining=%d data=%s", len(data), hex.EncodeToString(data))
					break
				}
				if data[0]>>4 != 4 {
					t.log.Printf("dropping non-IPv4 outbound packet data: remaining=%d version=%d", len(data), data[0]>>4)
					break
				}
				totalLen := int(binary.BigEndian.Uint16(data[2:4]))
				if totalLen < 20 {
					t.log.Printf("dropping malformed outbound IPv4 packet: totalLen=%d remaining=%d", totalLen, len(data))
					break
				}
				if totalLen > len(data) {
					t.log.Printf("buffering incomplete outbound IPv4 packet: totalLen=%d remaining=%d", totalLen, len(data))
					// Copy because data points at the reusable TUN read buffer.
					overflow = append(overflow[:0], data...)
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

				batch = append(batch, udpPacket{data: pkt, addr: raddr})
			}

			sent, err := flushBatch()
			if err != nil {
				if !isDone(ctx) {
					t.log.Printf("net write error: %v", err)
					time.Sleep(time.Second)
				}
				// WriteBatch should never report more sends than were requested,
				// but clamp defensively so the retry slice below cannot panic.
				if sent > len(batch) {
					sent = len(batch)
				}
				// Preserve unsent batched packets as raw bytes before the next TUN
				// read reuses buffer.
				overflow = copyPendingPackets(batch[sent:], data)
			}
			batch = batch[:0]
		}
	}()

	// Handle inbound traffic.
	wg.Add(1)
	go func() {
		defer wg.Done()

		// processDatagram applies the per-datagram inbound logic (heartbeat
		// handling, client registration check, protocol filter) and returns the
		// payload to forward to the TUN device, or nil if the datagram was
		// consumed or dropped. The returned slice is only valid for the duration
		// of this call (it aliases the read buffer), so callers must copy it if
		// they need to retain it.
		processDatagram := func(payload []byte, raddr *net.UDPAddr) []byte {
			if t.server {
				ipPkt := ipPacket(payload)

				if ipPkt.Version() != 4 {
					raddrStr := raddr.String()

					// Heartbeats are deliberately non-IP control messages carried on
					// the same UDP socket as tunneled packets.
					if strings.HasPrefix(string(payload), pingPrefix) {
						clientTunIp := strings.TrimPrefix(string(payload), pingPrefix)

						// Reject malformed heartbeats so garbage can't pollute the
						// tunnel-IP mapping or the logs.
						if net.ParseIP(clientTunIp) == nil {
							t.log.Printf("ignoring heartbeat with invalid tunnel IP %q from %s", clientTunIp, raddrStr)
							return nil
						}

						var session *clientSession
						sessionInterface, loaded := t.activeClients.LoadOrStore(raddrStr, &clientSession{
							lastActive: time.Now(),
						})
						session = sessionInterface.(*clientSession)
						if !loaded {
							t.log.Printf("new client connected: public=%s", raddrStr)
						}

						session.mu.Lock()
						session.lastActive = time.Now()

						needUpdate := false
						if _, ok := t.tunnelIPtoClient.Load(clientTunIp); !ok || session.tunnelIP == "" {
							needUpdate = true
							// A client may move between public addresses; keep only the
							// latest tunnel-IP mapping for this session.
							if session.tunnelIP != "" && session.tunnelIP != clientTunIp {
								t.tunnelIPtoClient.Delete(session.tunnelIP)
							}
							session.tunnelIP = clientTunIp
						}
						session.mu.Unlock()

						if needUpdate {
							// Store the source address as-is; the outbound path
							// type-asserts it back to *net.UDPAddr.
							t.tunnelIPtoClient.Store(clientTunIp, raddr)
							t.log.Printf("Updated tunnel IP for %s to %s", raddrStr, clientTunIp)
						}
						return nil
					}

					t.log.Printf("Received non-IPv4 data packet from %s. Dropping.", raddrStr)
					return nil
				}
			}

			// In server mode, only accept tunneled data from a client that has
			// registered itself with a heartbeat. This prevents arbitrary hosts
			// from injecting packets into the tunnel network.
			if t.server {
				if _, ok := t.activeClients.Load(raddr.String()); !ok {
					t.log.Printf("dropping inbound data from unregistered client: %s", raddr)
					return nil
				}
			}

			if protocolFilter.Filter(payload) {
				t.log.Printf("dropping inbound packet rejected by protocol filter: bytes=%d protocol=%d", len(payload), ipPacket(payload).Protocol())
				return nil
			}

			return payload
		}

		// groBuf accumulates the payloads that survive processDatagram so they
		// can be handed to a single iface.Write. Concatenating multiple packets
		// in one write is what lets the TUN library's GRO coalesce same-flow
		// packets; with one packet per write it can never merge anything.
		var groBuf []byte
		for {
			msgs, err := udpReceiver.readBatch()

			// With a partial batch ReadBatch may return some datagrams alongside
			// an error (e.g. a transient error partway through); process whatever
			// arrived before deciding how to handle the error.
			groBuf = groBuf[:0]
			for i := range msgs {
				msg := &msgs[i]
				if msg.N <= 0 {
					continue
				}
				raddr, ok := msg.Addr.(*net.UDPAddr)
				if !ok || raddr == nil {
					continue
				}
				payload := msg.Buffers[0][:msg.N]
				if out := processDatagram(payload, raddr); out != nil {
					groBuf = append(groBuf, out...)
				}
			}

			// Deliver any accumulated packets to the TUN device. The library's
			// virtioMakeGro coalesces same-flow packets within this single write;
			// errors here don't corrupt later packets since each Write is
			// independent.
			if len(groBuf) > 0 {
				nw, werr := iface.Write(groBuf)
				if werr != nil {
					if isDone(ctx) {
						return
					}
					t.log.Printf("tun write error: %v", werr)
				}
				if nw < len(groBuf) && werr == nil {
					// The library may accept a prefix of the concatenated packets
					// and report the rest as an incomplete trailing packet. The
					// consumed prefix was written; drop only the trailing remnant.
					t.log.Printf("tun write accepted %d of %d inbound bytes; dropping trailing remnant", nw, len(groBuf))
				}
			}

			if err != nil {
				if isDone(ctx) {
					return
				}
				if len(msgs) == 0 {
					// Nothing was read; the error applies to the whole batch.
					t.log.Printf("net read error: %v", err)
					time.Sleep(time.Second)
				} else {
					// Some datagrams were read and processed; log but don't sleep,
					// since data is still flowing.
					t.log.Printf("net read error (partial batch): %v", err)
				}
				continue
			}
			if len(msgs) == 0 {
				// ReadBatch returned 0 with no error. Avoid spinning.
				time.Sleep(time.Second)
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

					// If a heartbeat already moved this tunnel IP to a new public
					// address, keep the newer mapping.
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

func (t *tunnel) logConnectedClients(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.log.Printf("--- Connected clients ---")
			t.activeClients.Range(func(key, value interface{}) bool {
				session := value.(*clientSession)
				session.mu.Lock()
				tunIP := session.tunnelIP
				session.mu.Unlock()
				if tunIP != "" {
					t.log.Printf("  public=%s  tunnel=%s", key.(string), tunIP)
				} else {
					t.log.Printf("  public=%s  tunnel=(not yet assigned)", key.(string))
				}
				return true
			})
		}
	}
}

func isDone(ctx context.Context) bool {
	return ctx.Err() != nil
}
