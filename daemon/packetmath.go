package main

import "encoding/binary"

const (
	pmAddrFlagsOff = 8
	pmFlagOutbound = 1 << 17
	pmFlagLoopback = 1 << 18
	pmFlagIPv6     = 1 << 20
)

func pmAddrFlags(addr []byte) uint32 { return binary.LittleEndian.Uint32(addr[pmAddrFlagsOff:]) }
func pmSetAddrFlags(addr []byte, f uint32) {
	binary.LittleEndian.PutUint32(addr[pmAddrFlagsOff:], f)
}

func pmIsOutbound(addr []byte) bool { return pmAddrFlags(addr)&pmFlagOutbound != 0 }
func pmIsIPv6(addr []byte) bool     { return pmAddrFlags(addr)&pmFlagIPv6 != 0 }

func pmSetInbound(addr []byte) { pmSetAddrFlags(addr, pmAddrFlags(addr)&^pmFlagOutbound) }
func pmSetLoopback(addr []byte, on bool) {
	f := pmAddrFlags(addr)
	if on {
		f |= pmFlagLoopback
	} else {
		f &^= pmFlagLoopback
	}
	pmSetAddrFlags(addr, f)
}

func pmIPv4TCP(p []byte) (ihl int, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0, false
	}
	ihl = int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl+20 {
		return 0, false
	}
	if p[9] != 6 {
		return 0, false
	}
	return ihl, true
}

type pmParsed struct {
	ihl     int
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
	flags   byte
}

func pmParse(p []byte) (pmParsed, bool) {
	ihl, ok := pmIPv4TCP(p)
	if !ok {
		return pmParsed{}, false
	}
	tcp := p[ihl:]
	return pmParsed{
		ihl:     ihl,
		srcIP:   [4]byte(p[12:16]),
		dstIP:   [4]byte(p[16:20]),
		srcPort: binary.BigEndian.Uint16(tcp[0:2]),
		dstPort: binary.BigEndian.Uint16(tcp[2:4]),
		flags:   tcp[13],
	}, true
}

var pmLoopback = [4]byte{127, 0, 0, 1}

func pmRedirectOutbound(p []byte, ihl int, proxyPort uint16) {
	copy(p[12:16], pmLoopback[:])
	copy(p[16:20], pmLoopback[:])
	binary.BigEndian.PutUint16(p[ihl+2:ihl+4], proxyPort)
}

func pmRedirectReply(p []byte, ihl int, origDstIP, origSrcIP [4]byte, origDstPort uint16) {
	copy(p[12:16], origDstIP[:])
	copy(p[16:20], origSrcIP[:])
	binary.BigEndian.PutUint16(p[ihl:ihl+2], origDstPort)
}

func pmIsFinishing(flags byte) bool { return flags&0x05 != 0 }
