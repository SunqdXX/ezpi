package main

import (
	"encoding/binary"
	"testing"
)

func buildClientHelloPacket(t *testing.T, host string, seq uint32) []byte {
	t.Helper()
	rec := realClientHello(t, host)
	ihl, tcpHdr := 20, 20
	pkt := make([]byte, ihl+tcpHdr+len(rec))
	pkt[0] = 0x45
	pkt[9] = 6
	copy(pkt[12:16], []byte{192, 168, 1, 50})
	copy(pkt[16:20], []byte{128, 116, 5, 3})
	binary.BigEndian.PutUint16(pkt[ihl:ihl+2], 51000)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], 443)
	binary.BigEndian.PutUint32(pkt[ihl+4:ihl+8], seq)
	pkt[ihl+12] = 5 << 4
	copy(pkt[ihl+tcpHdr:], rec)
	setIPTotalLen(pkt)
	fixChecksums(pkt, ihl)
	return pkt
}

func TestDetectsClientHelloAndRejectsOther(t *testing.T) {
	real := realClientHello(t, "discord.com")
	if !isClientHello(real) {
		t.Error("genuine ClientHello not detected")
	}
	for _, bad := range [][]byte{
		nil, {}, {0x16}, {0x17, 0x03, 0x03, 0x00, 0x10},
		{0x16, 0x03, 0x01, 0x00, 0x10, 0x02},
	} {
		if isClientHello(bad) {
			t.Errorf("false positive on %v", bad)
		}
	}
}

func TestChecksumsAreValid(t *testing.T) {
	pkt := buildClientHelloPacket(t, "www.roblox.com", 1000)
	ihl := 20

	if got := ipChecksum(pkt[:ihl]); got != 0 {
		t.Errorf("IP checksum invalid: recomputing over the header+checksum gave 0x%04x, want 0", got)
	}
	if got := tcpChecksum(pkt, ihl); got != 0 {
		t.Errorf("TCP checksum invalid: got 0x%04x, want 0", got)
	}
}

func TestSplitReassemblesAndChecksums(t *testing.T) {
	seq := uint32(500000)
	pkt := buildClientHelloPacket(t, "gateway.discord.gg", seq)
	tp, ok := parseTCP(pkt)
	if !ok {
		t.Fatal("failed to parse the test packet")
	}
	original := append([]byte(nil), tp.payload()...)

	a, b := splitPackets(tp, splitOffset(tp.payload(), 2))

	pa, _ := parseTCP(a)
	pb, _ := parseTCP(b)

	if pa.seq != seq {
		t.Errorf("first segment seq = %d, want %d", pa.seq, seq)
	}
	if pb.seq != seq+uint32(len(pa.payload())) {
		t.Errorf("second seq = %d, want %d (a gap breaks reassembly)",
			pb.seq, seq+uint32(len(pa.payload())))
	}

	joined := append(append([]byte(nil), pa.payload()...), pb.payload()...)
	if string(joined) != string(original) {
		t.Fatal("split segments do not reassemble to the original handshake")
	}

	for name, seg := range map[string][]byte{"first": a, "second": b} {
		if ipChecksum(seg[:20]) != 0 {
			t.Errorf("%s segment has a bad IP checksum", name)
		}
		if tcpChecksum(seg, 20) != 0 {
			t.Errorf("%s segment has a bad TCP checksum", name)
		}
	}

	host := []byte("gateway.discord.gg")
	if contains(pa.payload(), host) {
		t.Error("first segment still holds the whole hostname")
	}
}

func TestFakePacketIsValidDecoy(t *testing.T) {
	pkt := buildClientHelloPacket(t, "www.roblox.com", 700)
	tp, _ := parseTCP(pkt)
	cfg := DesyncConfig{FakeSNI: "www.google.com", FakeTTL: 6, Foolings: []Fooling{FoolTTL}}

	fake := fakePacket(tp, cfg)
	if fake.TTL == 0 || fake.TTL > 12 {
		t.Errorf("fake TTL = %d, want a small value that dies before the server", fake.TTL)
	}
	fp, ok := parseTCP(fake.Data)
	if !ok {
		t.Fatal("fake packet does not parse as IPv4/TCP")
	}
	if !isClientHello(fp.payload()) {
		t.Fatal("fake payload is not a valid ClientHello, so a censor would ignore it")
	}
	if !contains(fp.payload(), []byte("www.google.com")) {
		t.Error("fake does not carry the decoy hostname")
	}
	if !contains(fp.payload(), []byte("roblox")) {
	} else {
		t.Error("fake leaked the real hostname")
	}
	if ipChecksum(fake.Data[:20]) != 0 || tcpChecksum(fake.Data, 20) != 0 {
		t.Error("fake packet has invalid checksums; a censor would drop it before inspecting")
	}
	if fp.seq != tp.seq {
		t.Errorf("fake seq = %d, want the real seq %d", fp.seq, tp.seq)
	}
}

func TestDesyncMethodsProducePackets(t *testing.T) {
	pkt := buildClientHelloPacket(t, "discord.com", 42)
	for _, m := range []DesyncMethod{DesyncFake, DesyncSplit, DesyncFakeSplit, DesyncDisorder} {
		cfg := defaultDesyncConfig()
		cfg.Method = m
		out, ok := Desync(pkt, cfg)
		if !ok || len(out) < 2 {
			t.Errorf("method %q produced %d packets, want >= 2", m, len(out))
		}
		for i, op := range out {
			if len(op.Data) < 40 {
				t.Errorf("method %q packet %d is too small to be valid", m, i)
			}
		}
	}
}

func TestNonHandshakePassesUntouched(t *testing.T) {
	pkt := make([]byte, 60)
	pkt[0] = 0x45
	pkt[9] = 6
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	pkt[32] = 5 << 4
	copy(pkt[40:], []byte("GET / HTTP/1.1"))
	setIPTotalLen(pkt)
	fixChecksums(pkt, 20)
	if _, ok := Desync(pkt, defaultDesyncConfig()); ok {
		t.Error("a non-handshake packet was mangled")
	}
}

func TestQUICInitialDetection(t *testing.T) {
	initial := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08}
	if !isQUICInitial(initial) {
		t.Error("QUIC v1 Initial not detected")
	}
	if isQUICInitial([]byte{0x40, 0, 0, 0, 0, 0}) {
		t.Error("short-header packet misread as Initial")
	}
	if isQUICInitial([]byte{0xc0, 0, 0, 0, 0, 0}) {
		t.Error("version-negotiation misread as Initial")
	}
}

func contains(h, n []byte) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if string(h[i:i+len(n)]) == string(n) {
			return true
		}
	}
	return false
}

func TestFoolingModesShapeTheDecoy(t *testing.T) {
	pkt := buildClientHelloPacket(t, "www.roblox.com", 5000)
	tp, _ := parseTCP(pkt)

	f := fakePacket(tp, DesyncConfig{FakeSNI: "www.google.com", Foolings: []Fooling{FoolBadSeq}})
	fp, _ := parseTCP(f.Data)
	if diff := int64(tp.seq) - int64(fp.seq); diff < 40000 && diff > -40000 {
		t.Errorf("badseq left the sequence too close: real=%d fake=%d", tp.seq, fp.seq)
	}
	if isClientHello(fp.payload()) == false {
		t.Error("badseq decoy is not a valid ClientHello")
	}

	f = fakePacket(tp, DesyncConfig{FakeSNI: "www.google.com", Foolings: []Fooling{FoolDataNoAck}})
	if f.Data[tp.ihl+13]&0x10 != 0 {
		t.Error("datanoack did not clear the ACK flag")
	}

	f = fakePacket(tp, DesyncConfig{FakeSNI: "www.google.com", Foolings: []Fooling{FoolBadSum}})
	if !f.BadChecksum {
		t.Error("badsum did not mark the packet for a corrupt checksum")
	}

	f = fakePacket(tp, DesyncConfig{FakeSNI: "www.google.com", FakeTTL: 5, Foolings: []Fooling{FoolTTL}})
	if f.TTL != 5 {
		t.Errorf("ttl fooling gave TTL %d, want 5", f.TTL)
	}
}

func TestMultisplitReassembles(t *testing.T) {
	pkt := buildClientHelloPacket(t, "gateway.discord.gg", 900000)
	tp, _ := parseTCP(pkt)
	original := append([]byte(nil), tp.payload()...)

	segs := multiSplit(tp, tp.payload())
	if len(segs) < 3 {
		t.Fatalf("multisplit gave %d segments, want at least 3", len(segs))
	}

	joined := make([]byte, 0, len(original))
	expectSeq := tp.seq
	for _, seg := range segs {
		sp, ok := parseTCP(seg)
		if !ok {
			t.Fatal("a multisplit segment does not parse")
		}
		if sp.seq != expectSeq {
			t.Errorf("segment seq = %d, want %d (gap breaks reassembly)", sp.seq, expectSeq)
		}
		joined = append(joined, sp.payload()...)
		expectSeq += uint32(len(sp.payload()))
		if ipChecksum(seg[:20]) != 0 || tcpChecksum(seg, 20) != 0 {
			t.Error("a multisplit segment has a bad checksum")
		}
	}
	if string(joined) != string(original) {
		t.Fatal("multisplit does not reassemble to the original")
	}

	host := []byte("gateway.discord.gg")
	for _, seg := range segs {
		sp, _ := parseTCP(seg)
		if contains(sp.payload(), host) {
			t.Error("a segment still holds the whole hostname")
		}
	}
}

func TestAllDesyncMethodsRun(t *testing.T) {
	pkt := buildClientHelloPacket(t, "discord.com", 1)
	for _, m := range []DesyncMethod{
		DesyncFake, DesyncSplit, DesyncFakeSplit, DesyncDisorder,
		DesyncMultisplit, DesyncMultidisorder,
	} {
		cfg := defaultDesyncConfig()
		cfg.Method = m
		out, ok := Desync(pkt, cfg)
		if !ok || len(out) < 2 {
			t.Errorf("method %q produced %d packets", m, len(out))
		}
	}
}
