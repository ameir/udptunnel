// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

const (
	icmp = 1
	tcp  = 6
	udp  = 17
)

type ipPacket []byte

func (ip ipPacket) Version() int {
	if len(ip) > 0 {
		return int(ip[0] >> 4)
	}
	return 0
}

func (ip ipPacket) Protocol() int {
	if len(ip) < 10 {
		return 0
	}
	return int(ip[9])
}

type protocolFilter struct{}

func newProtocolFilter() *protocolFilter {
	return &protocolFilter{}
}

func (pf *protocolFilter) Filter(b []byte) (drop bool) {
	// This logic assumes malformed IP packets are rejected by the Linux kernel.
	ip := ipPacket(b)
	if ip.Version() != 4 {
		return true // No support for tunneling IPv6
	}
	if ip.Protocol() != tcp && ip.Protocol() != udp {
		return ip.Protocol() != icmp // Always allow ping
	}
	return false
}
