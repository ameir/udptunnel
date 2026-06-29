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
const maxUDPRecvBatch = 32

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

type udpBatchReceiver struct {
	conn *ipv4.PacketConn
	// msgs is reused across reads. Each entry's Buffers points at a stable
	// backing buffer in bufs so ReadBatch can refill them in place.
	msgs []ipv4.Message
	bufs [][]byte
}

func newUDPBatchReceiver(conn *net.UDPConn) *udpBatchReceiver {
	r := &udpBatchReceiver{
		conn: ipv4.NewPacketConn(conn),
		msgs: make([]ipv4.Message, maxUDPRecvBatch),
		bufs: make([][]byte, maxUDPRecvBatch),
	}
	for i := range r.bufs {
		r.bufs[i] = make([]byte, 1<<18)
		// Pre-arm Buffers once; readBatch reuses the same backing slices.
		r.msgs[i].Buffers = [][]byte{r.bufs[i]}
	}
	return r
}

// readBatch drains up to maxUDPRecvBatch datagrams in one syscall
// (recvmmsg on Linux). It returns the slice of received messages (a sub-slice
// of the receiver's reusable msgs array) and the error from ReadBatch, if any.
//
// The returned messages are only valid until the next readBatch call, which
// reuses their backing buffers. Callers must copy any bytes they need to retain.
//
// ReadBatch with flags=0 is opportunistic: it returns whatever datagrams are
// currently queued without waiting to fill the batch, so latency is unaffected.
func (r *udpBatchReceiver) readBatch() ([]ipv4.Message, error) {
	n, err := r.conn.ReadBatch(r.msgs, 0)
	return r.msgs[:n], err
}
