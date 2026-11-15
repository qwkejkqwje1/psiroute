package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestTunSniffHTTPHost(t *testing.T) {
	b := []byte("GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.COM:8080\r\n\r\n")
	if h := sniffHost(b); h != "example.com" {
		t.Fatalf("host = %q", h)
	}
	if sniffWantMore(b) {
		t.Fatal("complete headers must not want more")
	}
	if !sniffWantMore([]byte("GET / HTTP/1.1\r\nHo")) {
		t.Fatal("partial headers must want more")
	}
	if sniffHost([]byte("SSH-2.0-OpenSSH")) != "" {
		t.Fatal("non-HTTP must give no host")
	}
}

func TestTunSniffTLSWantMore(t *testing.T) {
	if !sniffWantMore([]byte{0x16, 3, 1, 0x02, 0x00, 1, 2}) {
		t.Fatal("short ClientHello must want more")
	}
}

func TestTunDNSHelpers(t *testing.T) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'W', 'w', 'W', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	name, end := dnsQName(q)
	if name != "www.example.com" || end != len(q) {
		t.Fatalf("qname %q end %d", name, end)
	}
	r := dnsServfail(q)
	if r[0] != 0x12 || r[1] != 0x34 || r[2]&0x80 == 0 || r[3]&0x0f != 2 || len(r) != len(q) {
		t.Fatalf("bad servfail % x", r)
	}
	if _, end := dnsQName(q[:20]); end >= 0 {
		t.Fatal("truncated query must fail")
	}
}

func TestTunRevMap(t *testing.T) {
	var m revMap
	m.put(net.ParseIP("1.2.3.4"), "a.example", time.Minute)
	if m.get(netip.MustParseAddr("1.2.3.4")) != "a.example" {
		t.Fatal("lookup failed")
	}
	m.put(net.ParseIP("5.6.7.8"), "b.example", -time.Second)
	if m.get(netip.MustParseAddr("5.6.7.8")) != "" {
		t.Fatal("expired entry returned")
	}
}

func TestTunAppsAndTargets(t *testing.T) {
	l := tunSplitApps("Discord.exe; steam ,\n")
	if len(l) != 2 || !tunAppMatch("discord.exe", l) || !tunAppMatch("Steam.exe", l) || tunAppMatch("chrome.exe", l) {
		t.Fatalf("apps %v", l)
	}
	if tunUDPTarget(netip.MustParseAddr("224.0.0.251")) || tunUDPTarget(netip.MustParseAddr("255.255.255.255")) || !tunUDPTarget(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("udp target filter")
	}
	if !tunInternal(tunDNS4) || tunInternal(netip.MustParseAddr("172.19.0.5")) {
		t.Fatal("internal subnet")
	}
}

// computeIPv4TCPChecksum computes the standard RFC 793 TCP checksum over the
// IPv4 pseudo-header and TCP header+options.
func computeIPv4TCPChecksum(pkt []byte) uint16 {
	ihl := int(pkt[0]&0x0f) * 4
	tcpSeg := pkt[ihl:]
	tcpLen := uint16(len(tcpSeg))
	var sum uint32
	// Pseudo-header: src IP (12..16), dst IP (16..20), proto (6), tcpLen
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	sum += 6 + uint32(tcpLen)
	for i := 0; i < len(tcpSeg); i += 2 {
		if i == 16 {
			continue // skip checksum field itself
		}
		if i+1 < len(tcpSeg) {
			sum += uint32(binary.BigEndian.Uint16(tcpSeg[i : i+2]))
		} else {
			sum += uint32(tcpSeg[i]) << 8
		}
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestTunDynamicMTUAndTCPMSSClamping(t *testing.T) {
	// 1. Verify dynamic MTU and MSS calculation across tunnel cascades
	if got := effectiveTunMTU(1500, false, false); got != 1500 {
		t.Fatalf("plain TUN MTU = %d, want 1500", got)
	}
	if got := effectiveTunMTU(1500, false, true); got != 1380 {
		t.Fatalf("TUN+Psiphon MTU = %d, want 1380", got)
	}
	if got := effectiveTunMTU(1500, true, true); got != 1280 {
		t.Fatalf("TUN+WARP+Psiphon MTU = %d, want 1280", got)
	}
	if mss4 := effectiveTunMSS(1500, false, true, true); mss4 != 1180 {
		t.Fatalf("TUN+WARP+Psiphon IPv4 MSS = %d, want 1180", mss4)
	}
	if mss6 := effectiveTunMSS(1500, true, true, true); mss6 != 1160 {
		t.Fatalf("TUN+WARP+Psiphon IPv6 MSS = %d, want 1160", mss6)
	}

	// 2. Build a synthetic IPv4 TCP SYN packet with MSS=1460 (20B IPv4 + 28B TCP)
	pkt4 := make([]byte, 48)
	pkt4[0] = 0x45                                  // IPv4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(pkt4[2:4], 48)       // Total Length
	pkt4[8] = 64                                    // TTL
	pkt4[9] = 6                                     // Protocol = TCP
	copy(pkt4[12:16], []byte{172, 19, 0, 1})        // Src IP
	copy(pkt4[16:20], []byte{93, 184, 216, 34})     // Dst IP
	binary.BigEndian.PutUint16(pkt4[20:22], 51234)  // Src Port
	binary.BigEndian.PutUint16(pkt4[22:24], 443)    // Dst Port
	pkt4[32] = 0x70                                 // Data offset = 7 (28 bytes)
	pkt4[33] = 0x02                                 // Flags = SYN
	binary.BigEndian.PutUint16(pkt4[34:36], 64240)  // Window
	// TCP Options: NOP(1), NOP(1), MSS(kind=2, len=4, val=1460), NOP(1), EOL(0)
	copy(pkt4[40:48], []byte{1, 1, 2, 4, 0x05, 0xb4, 1, 0})
	binary.BigEndian.PutUint16(pkt4[36:38], computeIPv4TCPChecksum(pkt4))

	if !clampTCPMSS(pkt4, 1180, 1160) {
		t.Fatal("expected IPv4 SYN MSS 1460 to be clamped to 1180")
	}
	gotMSS := binary.BigEndian.Uint16(pkt4[44:46])
	if gotMSS != 1180 {
		t.Fatalf("clamped IPv4 MSS = %d, want 1180", gotMSS)
	}
	wantCsum := computeIPv4TCPChecksum(pkt4)
	gotCsum := binary.BigEndian.Uint16(pkt4[36:38])
	if gotCsum != wantCsum {
		t.Fatalf("incremental TCP checksum = %#04x, want %#04x", gotCsum, wantCsum)
	}

	// Second call on already clamped packet must be a no-op
	if clampTCPMSS(pkt4, 1180, 1160) {
		t.Fatal("already clamped packet should not be modified again")
	}

	// 3. Build a synthetic IPv6 TCP SYN+ACK packet with MSS=1440 (40B IPv6 + 24B TCP)
	pkt6 := make([]byte, 64)
	pkt6[0] = 0x60                            // IPv6
	binary.BigEndian.PutUint16(pkt6[4:6], 24) // Payload Length = 24
	pkt6[6] = 6                               // Next Header = TCP
	pkt6[7] = 64                              // Hop Limit
	pkt6[52] = 0x60                           // TCP Data Offset = 6 (24 bytes)
	pkt6[53] = 0x12                           // Flags = SYN | ACK
	copy(pkt6[60:64], []byte{2, 4, 0x05, 0xa0})
	if !clampTCPMSS(pkt6, 1180, 1160) {
		t.Fatal("expected IPv6 SYN+ACK MSS 1440 to be clamped to 1160")
	}
	if got6 := binary.BigEndian.Uint16(pkt6[62:64]); got6 != 1160 {
		t.Fatalf("clamped IPv6 MSS = %d, want 1160", got6)
	}
}
