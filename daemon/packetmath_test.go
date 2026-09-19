package main

import (
	"encoding/binary"
	"testing"
)

func buildV4TCP(srcIP, dstIP [4]byte, srcPort, dstPort uint16, flags byte) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6
	copy(p[12:16], srcIP[:])
	copy(p[16:20], dstIP[:])
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	p[33] = flags
	return p
}

func mkAddr(flags uint32) []byte {
	a := make([]byte, 64)
	pmSetAddrFlags(a, flags)
	return a
}

func TestPacketParseRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil, {}, {0x45}, make([]byte, 19),
		append([]byte{0x60}, make([]byte, 40)...),
		append([]byte{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 17}, make([]byte, 30)...),
	}
	for i, c := range cases {
		if _, ok := pmParse(c); ok {
			t.Errorf("case %d parsed as valid IPv4/TCP but should not", i)
		}
	}
}

func TestParseReadsFields(t *testing.T) {
	p := buildV4TCP([4]byte{192, 168, 1, 5}, [4]byte{128, 116, 5, 3}, 51234, 443, 0x02)
	pkt, ok := pmParse(p)
	if !ok {
		t.Fatal("valid packet rejected")
	}
	if pkt.srcPort != 51234 || pkt.dstPort != 443 {
		t.Errorf("ports wrong: %d -> %d", pkt.srcPort, pkt.dstPort)
	}
	if pkt.dstIP != [4]byte{128, 116, 5, 3} {
		t.Errorf("dstIP wrong: %v", pkt.dstIP)
	}
	if pkt.flags != 0x02 {
		t.Errorf("flags wrong: 0x%02x", pkt.flags)
	}
}

func TestOutboundThenReplyRoundTrips(t *testing.T) {
	app := [4]byte{192, 168, 1, 5}
	server := [4]byte{128, 116, 5, 3}
	const appPort, serverPort, proxyPort = 51234, 443, 8443

	out := buildV4TCP(app, server, appPort, serverPort, 0x02)
	pkt, _ := pmParse(out)
	pmRedirectOutbound(out, pkt.ihl, proxyPort)

	after, _ := pmParse(out)
	if after.dstIP != pmLoopback || after.srcIP != pmLoopback {
		t.Fatalf("outbound not redirected to loopback: %v -> %v", after.srcIP, after.dstIP)
	}
	if after.dstPort != proxyPort {
		t.Fatalf("outbound dstPort = %d, want proxy %d", after.dstPort, proxyPort)
	}
	if after.srcPort != appPort {
		t.Fatalf("app source port was altered: %d", after.srcPort)
	}

	reply := buildV4TCP(pmLoopback, pmLoopback, proxyPort, appPort, 0x10)
	rpkt, _ := pmParse(reply)
	pmRedirectReply(reply, rpkt.ihl, server, app, serverPort)

	final, _ := pmParse(reply)
	if final.srcIP != server {
		t.Errorf("reply srcIP = %v, want the real server %v", final.srcIP, server)
	}
	if final.dstIP != app {
		t.Errorf("reply dstIP = %v, want the app %v", final.dstIP, app)
	}
	if final.srcPort != serverPort {
		t.Errorf("reply srcPort = %d, want %d so the app's socket accepts it", final.srcPort, serverPort)
	}
	if final.dstPort != appPort {
		t.Errorf("reply dstPort = %d, want the app's port %d", final.dstPort, appPort)
	}
}

func TestAddressFlagsToggle(t *testing.T) {
	a := mkAddr(pmFlagOutbound)
	if !pmIsOutbound(a) {
		t.Fatal("outbound flag not read")
	}
	pmSetInbound(a)
	if pmIsOutbound(a) {
		t.Error("outbound flag not cleared")
	}
	pmSetLoopback(a, true)
	if pmAddrFlags(a)&pmFlagLoopback == 0 {
		t.Error("loopback flag not set")
	}
	pmSetLoopback(a, false)
	if pmAddrFlags(a)&pmFlagLoopback != 0 {
		t.Error("loopback flag not cleared")
	}
}

func TestFinishingDetection(t *testing.T) {
	if !pmIsFinishing(0x01) {
		t.Error("FIN not detected")
	}
	if !pmIsFinishing(0x04) {
		t.Error("RST not detected")
	}
	if pmIsFinishing(0x10) {
		t.Error("plain ACK misread as finishing")
	}
}
