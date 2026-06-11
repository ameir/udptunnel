// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"io"
	"net"

	"golang.org/x/net/ipv4"
)

const maxUDPSendBatch = 32

// udpPacket keeps the destination alongside the payload so one batch can
// contain packets for different clients in server mode.
type udpPacket struct {
	data []byte
	addr *net.UDPAddr
}

// copyPendingPackets detaches unsent packet bytes from the reusable TUN read
// buffer before retrying them on a later loop iteration.
func copyPendingPackets(packets []udpPacket, tail []byte) []byte {
	totalLen := len(tail)
	for _, packet := range packets {
		totalLen += len(packet.data)
	}
	if totalLen == 0 {
		return nil
	}

	out := make([]byte, 0, totalLen)
	for _, packet := range packets {
		out = append(out, packet.data...)
	}
	out = append(out, tail...)
	return out
}

type udpBatchSender struct {
	conn *ipv4.PacketConn
	// msgs is reused to avoid allocating the ipv4.Message slice for every TUN
	// read. Only the per-message Buffers slices are rebuilt.
	msgs []ipv4.Message
}

func newUDPBatchSender(conn *net.UDPConn) *udpBatchSender {
	return &udpBatchSender{
		conn: ipv4.NewPacketConn(conn),
		msgs: make([]ipv4.Message, maxUDPSendBatch),
	}
}

func (s *udpBatchSender) WriteBatch(packets []udpPacket) (int, error) {
	total := 0
	for total < len(packets) {
		end := total + maxUDPSendBatch
		if end > len(packets) {
			end = len(packets)
		}

		// ipv4.PacketConn.WriteBatch uses sendmmsg on Linux; chunk explicitly so
		// the reusable message slice stays bounded.
		msgs := s.msgs[:end-total]
		for i := range msgs {
			packet := packets[total+i]
			msgs[i] = ipv4.Message{
				Buffers: [][]byte{packet.data},
				Addr:    packet.addr,
			}
		}

		n, err := s.conn.WriteBatch(msgs, 0)
		clear(msgs)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
