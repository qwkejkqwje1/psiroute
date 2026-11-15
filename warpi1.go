package main

// Generators of signature packets (I1–I5 of AmneziaWG 1.5/2.0): the pre-handshake
// packet sequence is made to look like a complete multi-packet UDP protocol
// exchange that TSPU/DPI filters pass — a QUIC (HTTP/3) connection start with
// ECH + 0-RTT + 1-RTT frames, a MASQUE HTTP/3 CONNECT-UDP tunnel, a DNS query,
// a STUN exchange, or a SIP dialog.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strings"
)

// i1Profiles are the protocols the generator imitates.
var i1Profiles = []string{"quic", "masque", "dns", "stun", "sip"}

// i1Hosts are sites used when none is given.
var i1Hosts = []string{"www.google.com", "www.microsoft.com", "www.apple.com", "cdn.jsdelivr.net", "www.cloudflare.com", "dl.google.com"}

// genI1 makes the primary I1 signature packet in the AmneziaWG syntax.
// profile: quic | masque | dns | stun | sip | random ("" = quic); host: the site named in it.
func genI1(profile, host string) (sig, label string, err error) {
	i1, _, _, _, _, lbl, err := genI1Chain(profile, host)
	return i1, lbl, err
}

// genI1Chain builds a full 5-packet I1..I5 AmneziaWG CPS chain for the chosen
// UDP protocol profile (Priority 2: I1–I5 / MASQUE expansion).
func genI1Chain(profile, host string) (i1, i2, i3, i4, i5, label string, err error) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	switch profile {
	case "":
		profile = "quic"
	case "random":
		profile = i1Profiles[mrand.IntN(len(i1Profiles))]
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		if profile == "masque" {
			host = "consumer-masque.cloudflareclient.com"
		} else {
			host = i1Hosts[mrand.IntN(len(i1Hosts))]
		}
	}
	if !validHost(host) {
		return "", "", "", "", "", "", fmt.Errorf("неверное имя сайта %q", host)
	}
	label = profile + " (" + host + ")"
	dcidHex := fmt.Sprintf("%x", rnd(8))

	switch profile {
	case "masque":
		var b []byte
		if b, err = quicInitial(host); err != nil {
			return "", "", "", "", "", "", err
		}
		i1 = fmt.Sprintf("<b 0x%x>", b)
		// I2: QUIC v1 0-RTT Long Header (0xd0) + version 1 + DCID + HTTP/3 SETTINGS & QPACK stream preface
		i2 = fmt.Sprintf("<b 0xd10000000108%s004058><c><r 80>", dcidHex)
		// I3: QUIC v1 Handshake packet (0xe0) + DCID + SCID + simulated TLS Finished / H3 Extended CONNECT-UDP
		i3 = fmt.Sprintf("<b 0xe20000000108%s004074><t><c><r 104>", dcidHex)
		// I4: QUIC 1-RTT Short Header (0x43) carrying H3 Datagram / MASQUE Capsule frame
		i4 = fmt.Sprintf("<b 0x43%s0020><c><r 68>", dcidHex)
		// I5: QUIC 1-RTT Short Header (0x41) ACK + PING keepalive
		i5 = fmt.Sprintf("<b 0x41%s><t><c><r 36>", dcidHex)

	case "quic":
		var b []byte
		if b, err = quicInitial(host); err != nil {
			return "", "", "", "", "", "", err
		}
		i1 = fmt.Sprintf("<b 0x%x>", b)
		// I2: QUIC v1 Handshake packet
		i2 = fmt.Sprintf("<b 0xe10000000108%s004050><c><r 72>", dcidHex)
		// I3: QUIC 1-RTT HTTP/3 SETTINGS frame
		i3 = fmt.Sprintf("<b 0x42%s><c><r 56>", dcidHex)
		// I4: QUIC 1-RTT HTTP/3 HEADERS frame
		i4 = fmt.Sprintf("<b 0x43%s><t><c><r 48>", dcidHex)
		// I5: QUIC 1-RTT ACK frame
		i5 = fmt.Sprintf("<b 0x40%s><c><r 28>", dcidHex)

	case "dns":
		i1 = dnsI1(host)
		i2 = dnsI2HTTPS(host)
		i3 = stunI1()
		i4 = fmt.Sprintf("<b 0x40%s><c><r 24>", dcidHex)
		i5 = fmt.Sprintf("<b 0x41%s><t><r 20>", dcidHex)

	case "stun":
		i1, label = stunI1(), "stun"
		i2 = "<b 0x001100182112a442><r 12><b 0x00060009><rc 9><b 0x000000>"
		i3 = "<b 0x80c80006><t><c><r 20>"
		i4 = "<b 0x80c90001><c><r 16>"
		i5 = stunI1()

	case "sip":
		i1 = sipI1(host)
		i2 = stunI1()
		i3 = "<b 0x80c80006><t><c><r 24>"
		i4 = "<b 0x8000><c><t><r 32>"
		i5 = "<b 0x0d0a0d0a>"

	default:
		return "", "", "", "", "", "", fmt.Errorf("неизвестный вид пакета %q (бывают: quic, masque, dns, stun, sip, random)", profile)
	}
	return i1, i2, i3, i4, i5, label, nil
}

func validHost(h string) bool {
	if len(h) == 0 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func rnd(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// ---- QUIC v1 Initial (RFC 9000, RFC 9001) + TLS 1.3 ECH (0xfe0d) ----

var quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// quicInitialSize is the size browsers pad their first packet to.
const quicInitialSize = 1250

func hkdfLabel(secret []byte, label string, n int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	full := "tls13 " + label
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

// quicClientKeys derives the client Initial keys from the destination
// connection id.
func quicClientKeys(dcid []byte) (key, iv, hp []byte) {
	initial, err := hkdf.Extract(sha256.New, dcid, quicSaltV1)
	if err != nil {
		panic(err)
	}
	client := hkdfLabel(initial, "client in", 32)
	return hkdfLabel(client, "quic key", 16), hkdfLabel(client, "quic iv", 12), hkdfLabel(client, "quic hp", 16)
}

func quicVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
}

// quicSeal encrypts an Initial packet: header ends with the packet number
// (pnLen bytes, value pn), payload is the plaintext frames.
func quicSeal(dcid, header []byte, pnLen int, pn uint64, payload []byte) ([]byte, error) {
	key, iv, hp := quicClientKeys(dcid)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	ct := aead.Seal(nil, nonce, payload, header)
	if len(ct) < 4-pnLen+16 {
		return nil, errors.New("слишком короткий пакет QUIC")
	}
	hpb, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	hpb.Encrypt(mask, ct[4-pnLen:4-pnLen+16])
	out := append([]byte(nil), header...)
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		out[len(header)-pnLen+i] ^= mask[1+i]
	}
	return append(out, ct...), nil
}

// quicInitial builds the first packet of an HTTP/3 / MASQUE connection to host.
func quicInitial(host string) ([]byte, error) {
	dcid := rnd(8)
	const pnLen = 1
	pn := uint64(0)
	header := []byte{0xc0 | (pnLen - 1)}
	header = binary.BigEndian.AppendUint32(header, 1) // QUIC v1
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, 0) // empty source connection id (as Chrome)
	header = append(header, 0) // no token
	hello, err := tlsClientHello(host)
	if err != nil {
		return nil, err
	}
	payloadLen := quicInitialSize - (len(header) + 2 + pnLen) - 16
	frame := []byte{0x06, 0x00} // CRYPTO, offset 0
	frame = quicVarint(frame, uint64(len(hello)))
	frame = append(frame, hello...)
	if len(frame) > payloadLen {
		return nil, errors.New("TLS ClientHello не помещается в пакет QUIC")
	}
	payload := make([]byte, 0, payloadLen)
	lead := mrand.IntN(32)
	payload = append(payload, make([]byte, lead)...)
	payload = append(payload, 0x01) // PING
	payload = append(payload, frame...)
	payload = append(payload, make([]byte, payloadLen-len(payload))...)
	header = binary.BigEndian.AppendUint16(header, uint16(pnLen+payloadLen+16)|0x4000) // length, 2-byte varint
	header = append(header, byte(pn))
	return quicSeal(dcid, header, pnLen, pn, payload)
}

// buildGREASEECH constructs a realistic TLS 1.3 outer ECH extension (0xfe0d,
// draft-ietf-tls-esni) with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
// AES-128-GCM so DPI boxes see an Encrypted ClientHello handshake.
// If a real/fallback ECH config is cached for host, its config_id is used.
func buildGREASEECHForHost(host string) []byte {
	cfgID := rnd(1)[0]
	if cfg := cachedOrFallbackECH(host); len(cfg) >= 8 {
		cfgID = cfg[6]
	}
	var b []byte
	b = append(b, 0x00)                   // ECHClientHelloType = outer (0)
	b = append(b, 0x00, 0x01, 0x00, 0x01) // KDF = HKDF-SHA256 (1), AEAD = AES-128-GCM (1)
	b = append(b, cfgID)                  // config_id
	enc := rnd(32)                        // X25519 ephemeral public key (32 bytes)
	b = binary.BigEndian.AppendUint16(b, uint16(len(enc)))
	b = append(b, enc...)
	payload := rnd(144) // encrypted inner ClientHello payload
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	b = append(b, payload...)
	return b
}

func buildGREASEECH() []byte {
	return buildGREASEECHForHost("")
}

// tlsClientHello is a TLS 1.3 ClientHello as browsers send it over QUIC:
// TLS 1.3 cipher suites, SNI, ALPN h3, X25519 key share, ECH (0xfe0d), and
// QUIC transport parameters (including H3 datagram support for MASQUE).
func tlsClientHello(host string) ([]byte, error) {
	grease := func() uint16 { g := byte(mrand.IntN(16)<<4 | 0x0a); return uint16(g)<<8 | uint16(g) }
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	ext := func(b []byte, typ uint16, body []byte) []byte {
		b = binary.BigEndian.AppendUint16(b, typ)
		b = u16(b, len(body))
		return append(b, body...)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var exts []byte
	exts = ext(exts, grease(), nil)
	// server_name
	sn := u16(nil, len(host)+3)
	sn = append(sn, 0)
	sn = u16(sn, len(host))
	sn = append(sn, host...)
	exts = ext(exts, 0x0000, sn)
	// supported_groups: GREASE, x25519, secp256r1, secp384r1
	exts = ext(exts, 0x000a, []byte{0, 8, byte(grease() >> 8), byte(grease() >> 8), 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
	// signature_algorithms
	sa := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	sab := u16(nil, 2*len(sa))
	for _, v := range sa {
		sab = binary.BigEndian.AppendUint16(sab, v)
	}
	exts = ext(exts, 0x000d, sab)
	// ALPN h3
	exts = ext(exts, 0x0010, []byte{0, 3, 2, 'h', '3'})
	// supported_versions: GREASE, TLS 1.3
	g := grease()
	exts = ext(exts, 0x002b, []byte{4, byte(g >> 8), byte(g), 0x03, 0x04})
	// psk_key_exchange_modes: psk_dhe_ke
	exts = ext(exts, 0x002d, []byte{1, 1})
	// key_share: x25519
	ks := u16(nil, 2+2+32)
	ks = append(ks, 0x00, 0x1d, 0x00, 0x20)
	ks = append(ks, key.PublicKey().Bytes()...)
	exts = ext(exts, 0x0033, ks)
	// compress_certificate: brotli
	exts = ext(exts, 0x001b, []byte{2, 0, 2})
	// Encrypted ClientHello (0xfe0d)
	exts = ext(exts, 0xfe0d, buildGREASEECHForHost(host))
	// quic_transport_parameters (including max_datagram_frame_size for MASQUE RFC 9297)
	tp := func(b []byte, id uint64, val []byte) []byte {
		b = quicVarint(b, id)
		b = quicVarint(b, uint64(len(val)))
		return append(b, val...)
	}
	vi := func(v uint64) []byte { return quicVarint(nil, v) }
	var tps []byte
	tps = tp(tps, 0x01, vi(30000))    // max_idle_timeout
	tps = tp(tps, 0x03, vi(1472))     // max_udp_payload_size
	tps = tp(tps, 0x04, vi(15728640)) // initial_max_data
	tps = tp(tps, 0x05, vi(6291456))  // initial_max_stream_data_bidi_local
	tps = tp(tps, 0x06, vi(6291456))  // initial_max_stream_data_bidi_remote
	tps = tp(tps, 0x07, vi(6291456))  // initial_max_stream_data_uni
	tps = tp(tps, 0x08, vi(100))      // initial_max_streams_bidi
	tps = tp(tps, 0x09, vi(103))      // initial_max_streams_uni
	tps = tp(tps, 0x0f, nil)          // initial_source_connection_id (empty)
	tps = tp(tps, 0x20, vi(65536))    // max_datagram_frame_size (RFC 9221 / MASQUE)
	tps = tp(tps, 0x2ab2, nil)        // grease_quic_bit
	exts = ext(exts, 0x0039, tps)
	exts = ext(exts, grease(), []byte{0})

	body := []byte{0x03, 0x03}
	body = append(body, rnd(32)...)
	body = append(body, 0)                                        // no legacy session id over QUIC
	body = append(body, 0, 6, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03) // TLS 1.3 suites
	body = append(body, 1, 0)                                     // no compression
	body = u16(body, len(exts))
	body = append(body, exts...)
	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...), nil
}

// ---- other protocols ----

func dnsI1(host string) string {
	var q []byte
	for _, l := range strings.Split(host, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1) // root, type A, class IN
	pad := 40 + mrand.IntN(120)
	opt := []byte{0, 0, 41, 0x10, 0, 0, 0, 0, 0} // root, OPT, 4096, rcode/flags
	opt = binary.BigEndian.AppendUint16(opt, uint16(pad+4))
	opt = binary.BigEndian.AppendUint16(opt, 12) // padding
	opt = binary.BigEndian.AppendUint16(opt, uint16(pad))
	head := []byte{0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1} // RD+AD, 1 question, 1 additional
	return fmt.Sprintf("<r 2><b 0x%x%x%x><r %d>", head, q, opt, pad)
}

// dnsI2HTTPS builds a secondary DNS query for RRType 65 (HTTPS/SVCB + ECH)
// as the I2 packet in the DNS signature chain.
func dnsI2HTTPS(host string) string {
	var q []byte
	for _, l := range strings.Split(host, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 65, 0, 1) // root, type HTTPS (65), class IN
	head := []byte{0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 0}
	return fmt.Sprintf("<r 2><b 0x%x%x>", head, q)
}

func stunI1() string {
	n := 4 * (4 + mrand.IntN(5))
	h := []byte{0x00, 0x01}
	h = binary.BigEndian.AppendUint16(h, uint16(4+n))
	h = append(h, 0x21, 0x12, 0xa4, 0x42)
	return fmt.Sprintf("<b 0x%x><r 12><b 0x8022%04x><rc %d>", h, n, n)
}

func sipI1(host string) string {
	t := func(s string) string { return fmt.Sprintf("<b 0x%x>", s) }
	return t("OPTIONS sip:"+host+" SIP/2.0\r\nVia: SIP/2.0/UDP 192.168."+fmt.Sprint(mrand.IntN(255))+"."+fmt.Sprint(2+mrand.IntN(250))+":5060;branch=z9hG4bK") +
		"<rc 10>" + t("\r\nFrom: <sip:") + "<rc 8>" + t("@"+host+">;tag=") + "<rd 8>" + t("\r\nTo: <sip:"+host+">\r\nCall-ID: ") + "<rc 16>" +
		t("\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nUser-Agent: Linphone/5.2.5\r\nContent-Length: 0\r\n\r\n")
}
