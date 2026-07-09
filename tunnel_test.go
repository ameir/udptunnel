// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func TestRegisterClientHeartbeatMovesTunnelIPToLatestPublicAddr(t *testing.T) {
	tun := newTestServerTunnel()

	oldAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 10000}
	newAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 20000}

	tun.registerClientHeartbeat("10.0.0.2", oldAddr)
	tun.registerClientHeartbeat("10.0.0.2", newAddr)

	got := loadClientAddrForTunnelIP(t, tun, "10.0.0.2")
	if got.String() != newAddr.String() {
		t.Fatalf("tunnel IP mapped to %s, want %s", got, newAddr)
	}

	if _, ok := tun.activeClients[oldAddr.AddrPort()]; !ok {
		t.Fatalf("old client session was removed; cleanup should age it out later")
	}
	if _, ok := tun.activeClients[newAddr.AddrPort()]; !ok {
		t.Fatalf("new client session missing")
	}
}

func TestRegisterClientHeartbeatRemovesOldTunnelIPForSamePublicAddr(t *testing.T) {
	tun := newTestServerTunnel()
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 10000}

	tun.registerClientHeartbeat("10.0.0.2", addr)
	tun.registerClientHeartbeat("10.0.0.3", addr)

	if _, ok := tun.tunnelIPtoClient.Load(ip4KeyFromString("10.0.0.2")); ok {
		t.Fatalf("old tunnel IP mapping still exists")
	}

	got := loadClientAddrForTunnelIP(t, tun, "10.0.0.3")
	if got.String() != addr.String() {
		t.Fatalf("new tunnel IP mapped to %s, want %s", got, addr)
	}
}

func newTestServerTunnel() *tunnel {
	return &tunnel{
		server:           true,
		log:              discardLogger{},
		activeClients:    make(map[netip.AddrPort]*clientSession),
		tunnelIPtoClient: &sync.Map{},
	}
}

func loadClientAddrForTunnelIP(t *testing.T, tun *tunnel, tunnelIP string) *net.UDPAddr {
	t.Helper()

	v, ok := tun.tunnelIPtoClient.Load(ip4KeyFromString(tunnelIP))
	if !ok {
		t.Fatalf("no mapping found for tunnel IP %s", tunnelIP)
	}
	addr, ok := v.(*net.UDPAddr)
	if !ok {
		t.Fatalf("mapping for tunnel IP %s has type %T, want *net.UDPAddr", tunnelIP, v)
	}
	return addr
}
