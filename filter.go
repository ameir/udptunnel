// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import "net"

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
	if len(ip) > 9 && ip.Version() == 4 {
		return int(ip[9])
	}
	return 0
}

func (ip ipPacket) AddressesV4() (src, dst [4]byte) {
	if len(ip) >= 20 && ip.Version() == 4 {
		copy(src[:], ip[12:16])
		copy(dst[:], ip[16:20])
	}
	return
}

// AddressesV4NetIP returns the source and destination IPv4 addresses as net.IP.
// It returns nil IPs if the packet is not IPv4 or is too short.
func (ip ipPacket) AddressesV4NetIP() (src, dst net.IP) {
	if len(ip) < 20 || ip.Version() != 4 { // Check length and version
		return nil, nil
	}
	return net.IP(ip[12:16]), net.IP(ip[16:20])
}

func (ip ipPacket) Body() []byte {
	if ip.Version() != 4 {
		return nil // No support for IPv6
	}
	n := int(ip[0] & 0x0f)
	if n < 5 || n > 15 || len(ip) < 4*n {
		return nil
	}
	return ip[4*n:]
}

type portFilter struct{}

func newPortFilter() *portFilter {
	return &portFilter{}
}
func (sf *portFilter) Filter(b []byte) (drop bool) {
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
