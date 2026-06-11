// Copyright 2017, The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestUDPBatchSenderSendmmsg(t *testing.T) {
	server := listenUDPTestSocket(t)
	defer server.Close()

	client := listenUDPTestSocket(t)
	defer client.Close()

	sender := newUDPBatchSender(client)

	dst := server.LocalAddr().(*net.UDPAddr)
	packetCount := maxUDPSendBatch*2 + 3
	packets := make([]udpPacket, packetCount)
	for i := range packets {
		packets[i] = udpPacket{
			data: []byte{byte(i)},
			addr: dst,
		}
	}
	n, err := sender.WriteBatch(packets)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(packets) {
		t.Fatalf("WriteBatch sent %d packets, want %d", n, len(packets))
	}

	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	for _, packet := range packets {
		n, _, err := server.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := buf[:n], packet.data; !bytes.Equal(got, want) {
			t.Fatalf("ReadFromUDP = %v, want %v", got, want)
		}
	}
}

func TestCopyPendingPackets(t *testing.T) {
	got := copyPendingPackets([]udpPacket{
		{data: []byte{1, 2}},
		{data: []byte{3}},
	}, []byte{4, 5})

	want := []byte{1, 2, 3, 4, 5}
	if !bytes.Equal(got, want) {
		t.Fatalf("copyPendingPackets = %v, want %v", got, want)
	}
}

func listenUDPTestSocket(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("local UDP sockets are not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	return conn
}
