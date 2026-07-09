# UDP virtual private tunnel daemon #

## Introduction ##

This repository contains a simple implementation of a point-to-point virtual
private network by opening a TUN device and transferring raw traffic over UDP.
This VPN was designed to create a tunnel between two hosts:
1. A client host operating behind an obtrusive NAT which drops TCP connections
frequently, but happens to pass UDP traffic reliably.
2. A server host that is internet-accessible.

TUN traffic is sent ad-verbatim between the two endpoints via unencrypted
UDP packets. Thus, this should only be used if a more secure protocol
(like SSH; see [github.com/dsnet/sshtunnel](https://github.com/dsnet/sshtunnel))
is running on top of this VPN. Users of udptunnel should also setup firewall
rules as a secondary measure to restrict malicious traffic.

This only supports Linux.

## Usage ##

Build the daemon:

```
go install github.com/dsnet/udptunnel@latest
```

Or build release binaries for Linux amd64, armv7, and arm64 from a checkout:

```
./build.sh
```

The build script writes binaries to `dist/` and creates `dist/sha256sum.txt`.

Create a server configuration file:

```javascript
{
	"TunnelAddress": "10.0.0.1",
	"NetworkAddress": ":8000"
}
```

The `NetworkAddress` with an empty host indicates that the daemon is operating
in server mode. The server binds the specified UDP port and learns clients from
their heartbeats.

Create a client configuration file:

```javascript
{
	"TunnelAddress": "10.0.0.2",
	"NetworkAddress": "server.example.com:8000",
	"HeartbeatInterval": 30
}
```

The host `server.example.com` is assumed to resolve to some address where the
client can reach the server. In client mode, the daemon resolves the server
name periodically and sends heartbeat messages to keep NAT state open. If the
client's public UDP address changes, the server updates its mapping from the
client's private tunnel address to the latest public address.

Start the daemon on both the client and server (assuming `$GOPATH/bin` is in your `$PATH`):

```
root@server.example.com $ udptunnel /path/to/config.json
root@client.example.com $ udptunnel /path/to/config.json
```

Try accessing the other endpoint (example is for client to server):

```
user@client.example.com $ ping 10.0.0.1
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_req=1 ttl=64 time=56.7 ms
64 bytes from 10.0.0.1: icmp_req=2 ttl=64 time=58.7 ms
64 bytes from 10.0.0.1: icmp_req=3 ttl=64 time=50.1 ms
64 bytes from 10.0.0.1: icmp_req=4 ttl=64 time=51.6 ms


user@client.example.com $ nmap 10.0.0.1
Host is up (0.063s latency).
PORT   STATE SERVICE
22/tcp open  ssh


user@client.example.com $ ssh 10.0.0.1
Password: ...
```

The above example shows the client trying to communicate with the server,
which is addressable at `10.0.0.1`. The example commands can be done from the
server by dialing the client at `10.0.0.2`, instead.

## Configuration ##

The configuration file is JSON. Supported fields are:

* `LogFile`: Optional path for daemon logs. Logs go to stderr when omitted.
* `TunnelDevice`: Optional TUN device name. The kernel chooses a name when
  omitted.
* `TunnelAddress`: Required private IPv4 address for this endpoint. Each
  endpoint must use a different address in the same `/24`, such as
  `10.0.0.1` and `10.0.0.2`.
* `NetworkAddress`: Required UDP address. Use `":PORT"` for server mode and
  `"HOST:PORT"` for client mode.
* `HeartbeatInterval`: Optional client heartbeat interval in seconds. The
  default is `30`.
* `DisableGsoGro`: Optional boolean. Leave it as `false` unless you need to
  disable TUN GSO/GRO offload for kernel or environment compatibility.

Only IPv4 tunnel traffic is forwarded. TCP, UDP, and ICMP packets are allowed;
other protocols and IPv6 packets are dropped.
