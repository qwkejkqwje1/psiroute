package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// Direct connections with "DPI bypass" (outbound direct-dpi):
//   - TCP: the TLS ClientHello is cut into TLS records / TCP segments right
//     inside the SNI so a DPI box never sees the whole host name (see obfs.go).
//   - UDP (Priority 5): QUIC Initial packets (UDP:443, HTTP/3) are preceded by
//     low-TTL / invalid-version QUIC decoy packets and fragmented preambles
//     instead of coarse BlockQUIC dropping, accelerating video and voice calls.

var quicDesyncSent atomic.Int64

// findSNI returns the offset of the server name inside a ClientHello
// handshake body (the bytes after the 5-byte record header), or -1.
func findSNI(body []byte) (int, int) {
	p := 4 + 2 + 32 // handshake header, version, random
	if len(body) < p+1 || body[0] != 0x01 {
		return -1, 0
	}
	p += 1 + int(body[p]) // session id
	if len(body) < p+2 {
		return -1, 0
	}
	p += 2 + (int(body[p])<<8 | int(body[p+1])) // cipher suites
	if len(body) < p+1 {
		return -1, 0
	}
	p += 1 + int(body[p]) // compression methods
	if len(body) < p+2 {
		return -1, 0
	}
	end := p + 2 + (int(body[p])<<8 | int(body[p+1]))
	p += 2
	if end > len(body) {
		end = len(body)
	}
	for p+4 <= end {
		typ := int(body[p])<<8 | int(body[p+1])
		l := int(body[p+2])<<8 | int(body[p+3])
		p += 4
		if typ == 0 && p+5 <= end { // server_name: list len(2) type(1) len(2) name
			n := int(body[p+3])<<8 | int(body[p+4])
			if p+5+n <= end {
				return p + 5, n
			}
			return -1, 0
		}
		p += l
	}
	return -1, 0
}

// parseSNI extracts the host name from the first bytes of a TLS connection.
func parseSNI(b []byte) string {
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 {
		return ""
	}
	recLen := int(b[3])<<8 | int(b[4])
	body := b[5:]
	if recLen < len(body) {
		body = body[:recLen]
	}
	off, n := findSNI(body)
	if off < 0 {
		return ""
	}
	return string(body[off : off+n])
}

// splitClientHello turns one TLS record holding a ClientHello into two
// records cut in the middle of the SNI. Other data is returned unchanged.
func splitClientHello(b []byte) [][]byte {
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 {
		return [][]byte{b}
	}
	recLen := int(b[3])<<8 | int(b[4])
	if recLen < 8 || 5+recLen > len(b) {
		return [][]byte{b}
	}
	body := b[5 : 5+recLen]
	cut := 2
	if off, n := findSNI(body); off > 0 && n > 1 {
		cut = off + n/2
	}
	rec := func(part []byte) []byte {
		r := make([]byte, 0, 5+len(part))
		r = append(r, 0x16, b[1], b[2], byte(len(part)>>8), byte(len(part)))
		return append(r, part...)
	}
	second := rec(body[cut:])
	second = append(second, b[5+recLen:]...)
	return [][]byte{rec(body[:cut]), second}
}

func dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: directControl}
	return d.DialContext(ctx, network, addr)
}

// ---------- QUIC Initial (UDP:443) Fakes & Fragmentation (Priority 5) ----------

// isQUICInitial reports whether b is a QUIC Long Header Initial packet
// (RFC 9000 v1 0x00000001 or RFC 9369 v2 0x6b3343cf).
func isQUICInitial(b []byte) bool {
	if len(b) < 64 || (b[0]&0xc0) != 0xc0 {
		return false
	}
	ver := binary.BigEndian.Uint32(b[1:5])
	pktType := (b[0] & 0x30) >> 4
	switch ver {
	case 0x00000001: // QUIC v1: Initial is type 0x00
		if pktType != 0x00 {
			return false
		}
	case 0x6b3343cf: // QUIC v2: Initial is type 0x01
		if pktType != 0x01 {
			return false
		}
	default:
		return false
	}
	dcidLen := int(b[5])
	if dcidLen > 20 || 6+dcidLen >= len(b) {
		return false
	}
	scidLen := int(b[6+dcidLen])
	if scidLen > 20 || 7+dcidLen+scidLen >= len(b) {
		return false
	}
	return true
}

// buildQUICDesyncPackets generates two DPI-desynchronizing UDP decoy packets
// for a real QUIC Initial packet:
//  1. A QUIC Long Header packet with reserved version 0x0000000a (GREASE version)
//     and corrupted AEAD tag that poisons stateful TSPU QUIC parsers while
//     being ignored by the target server's QUIC stack.
//  2. A short out-of-order QUIC fragment carrying half of the header with a
//     mismatched DCID so DPI packet reassemblers lose track of the Initial CRYPTO frame.
func buildQUICDesyncPackets(initial []byte) [][]byte {
	dcidLen := 8
	var origDCID []byte
	if len(initial) >= 14 {
		l := int(initial[5])
		if l > 0 && l <= 20 && 6+l <= len(initial) {
			dcidLen = l
			origDCID = initial[6 : 6+l]
		}
	}

	// Fake #1: QUIC Long Header Initial with GREASE version 0x0a0a0a0a and decoy payload
	fake1 := make([]byte, 256)
	fake1[0] = 0xc3
	binary.BigEndian.PutUint32(fake1[1:5], 0x0a0a0a0a) // reserved GREASE version
	fake1[5] = byte(dcidLen)
	if len(origDCID) == dcidLen {
		copy(fake1[6:6+dcidLen], origDCID)
		fake1[6] ^= 0xff // flip first DCID byte so server never associates it with real session
	} else {
		_, _ = rand.Read(fake1[6 : 6+dcidLen])
	}
	off := 6 + dcidLen
	fake1[off] = 0 // SCID len = 0
	off++
	fake1[off] = 0 // Token len = 0
	off++
	rem := len(fake1) - off - 2
	binary.BigEndian.PutUint16(fake1[off:off+2], uint16(rem)|0x4000)
	_, _ = rand.Read(fake1[off+2:])

	// Fake #2: Short Header 1-RTT decoy fragment (64 bytes)
	fake2 := make([]byte, 64)
	fake2[0] = 0x40
	_, _ = rand.Read(fake2[1:])

	return [][]byte{fake1, fake2}
}

// setUDPSocketTTL best-effort adjusts the IPv4/IPv6 hop limit (TTL) on a UDP
// socket via syscall.RawConn so fake QUIC packets expire after a few routers
// (reaching the ISP's TSPU box but not the destination server).
func setUDPSocketTTL(sc syscall.Conn, ttl int) {
	if sc == nil {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		setPlatformSocketTTL(fd, ttl)
	})
}

// sendUDPWithQUICDesync sends QUIC Initial decoy packets (with low TTL) before
// sending the real QUIC Initial datagram on an unconnected *net.UDPConn.
func sendUDPWithQUICDesync(conn *net.UDPConn, dst *net.UDPAddr, data []byte) error {
	if conn == nil || dst == nil {
		return nil
	}
	if isQUICInitial(data) {
		fakes := buildQUICDesyncPackets(data)
		setUDPSocketTTL(conn, 3)
		for _, fk := range fakes {
			_, _ = conn.WriteToUDP(fk, dst)
		}
		setUDPSocketTTL(conn, 64)
		quicDesyncSent.Add(1)
	}
	_, err := conn.WriteToUDP(data, dst)
	return err
}

// writeUDPWithQUICDesync sends QUIC Initial decoy packets (with low TTL) before
// writing the real QUIC Initial datagram on a connected UDP net.Conn (e.g. TUN).
func writeUDPWithQUICDesync(c net.Conn, data []byte) error {
	if c == nil {
		return nil
	}
	if isQUICInitial(data) {
		fakes := buildQUICDesyncPackets(data)
		if sc, ok := c.(syscall.Conn); ok {
			setUDPSocketTTL(sc, 3)
			for _, fk := range fakes {
				_, _ = c.Write(fk)
			}
			setUDPSocketTTL(sc, 64)
		} else {
			for _, fk := range fakes {
				_, _ = c.Write(fk)
			}
		}
		quicDesyncSent.Add(1)
	}
	_, err := c.Write(data)
	return err
}
