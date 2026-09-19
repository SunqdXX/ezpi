package main

import (
	"encoding/binary"
	"errors"
	"strings"
)

type DesyncMethod string

const (
	DesyncFake          DesyncMethod = "fake"
	DesyncSplit         DesyncMethod = "split"
	DesyncFakeSplit     DesyncMethod = "fakesplit"
	DesyncDisorder      DesyncMethod = "disorder"
	DesyncMultisplit    DesyncMethod = "multisplit"
	DesyncMultidisorder DesyncMethod = "multidisorder"
)

type OutPacket struct {
	Data        []byte
	TTL         uint8
	BadChecksum bool
}

type Fooling string

const (
	FoolBadSum    Fooling = "badsum"
	FoolBadSeq    Fooling = "badseq"
	FoolDataNoAck Fooling = "datanoack"
	FoolTTL       Fooling = "ttl"
)

type DesyncConfig struct {
	Method   DesyncMethod
	FakeTTL  uint8
	FakeSNI  string
	Foolings []Fooling
	SplitPos int
	BadSum   bool
}

func (c DesyncConfig) foolings() []Fooling {
	out := append([]Fooling(nil), c.Foolings...)
	if c.BadSum && !containsFool(out, FoolBadSum) {
		out = append(out, FoolBadSum)
	}
	if len(out) == 0 {
		out = []Fooling{FoolBadSum}
	}
	return out
}

func containsFool(fs []Fooling, f Fooling) bool {
	for _, x := range fs {
		if x == f {
			return true
		}
	}
	return false
}

func defaultDesyncConfig() DesyncConfig {
	return DesyncConfig{
		Method:   DesyncFakeSplit,
		FakeTTL:  6,
		FakeSNI:  "www.google.com",
		SplitPos: 2,
	}
}

var errNotHandshake = errors.New("packet does not carry a TLS ClientHello")

type tcpPacket struct {
	raw     []byte
	ihl     int
	dataOff int
	seq     uint32
}

func parseTCP(pkt []byte) (*tcpPacket, bool) {
	ihl, ok := pmIPv4TCP(pkt)
	if !ok {
		return nil, false
	}
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return nil, false
	}
	dataOffWords := int(tcp[12] >> 4)
	if dataOffWords < 5 || ihl+dataOffWords*4 > len(pkt) {
		return nil, false
	}
	return &tcpPacket{
		raw:     pkt,
		ihl:     ihl,
		dataOff: ihl + dataOffWords*4,
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
	}, true
}

func (p *tcpPacket) payload() []byte { return p.raw[p.dataOff:] }

func Desync(pkt []byte, cfg DesyncConfig) ([]OutPacket, bool) {
	tp, ok := parseTCP(pkt)
	if !ok {
		return nil, false
	}
	payload := tp.payload()
	if !isClientHello(payload) {
		return nil, false
	}

	switch cfg.Method {
	case DesyncFake:
		return []OutPacket{
			fakePacket(tp, cfg),
			{Data: clone(pkt)},
		}, true

	case DesyncSplit:
		a, b := splitPackets(tp, splitOffset(payload, cfg.SplitPos))
		return []OutPacket{{Data: a}, {Data: b}}, true

	case DesyncDisorder:
		a, b := splitPackets(tp, splitOffset(payload, cfg.SplitPos))
		return []OutPacket{{Data: b}, {Data: a}}, true

	case DesyncFakeSplit:
		a, b := splitPackets(tp, splitOffset(payload, cfg.SplitPos))
		return []OutPacket{
			fakePacket(tp, cfg),
			{Data: a},
			{Data: b},
		}, true

	case DesyncMultisplit:
		segs := multiSplit(tp, payload)
		out := make([]OutPacket, 0, len(segs))
		for _, seg := range segs {
			out = append(out, OutPacket{Data: seg})
		}
		return out, len(out) > 1

	case DesyncMultidisorder:
		segs := multiSplit(tp, payload)
		out := make([]OutPacket, 0, len(segs))
		for i := len(segs) - 1; i >= 0; i-- {
			out = append(out, OutPacket{Data: segs[i]})
		}
		return out, len(out) > 1
	}
	return nil, false
}

func multiSplit(tp *tcpPacket, payload []byte) [][]byte {
	cuts := splitPoints(payload)
	if len(cuts) == 0 {
		a, b := splitPackets(tp, splitOffset(payload, 2))
		return [][]byte{a, b}
	}
	var segs [][]byte
	prev := 0
	for _, c := range append(cuts, len(payload)) {
		if c <= prev || c > len(payload) {
			continue
		}
		seg := make([]byte, tp.dataOff+(c-prev))
		copy(seg, tp.raw[:tp.dataOff])
		copy(seg[tp.dataOff:], payload[prev:c])
		setTCPSeq(seg, tp.ihl, tp.seq+uint32(prev))
		setIPTotalLen(seg)
		fixChecksums(seg, tp.ihl)
		segs = append(segs, seg)
		prev = c
	}
	return segs
}

func splitPoints(payload []byte) []int {
	hs, ok := handshakeBytes(payload)
	if !ok {
		return nil
	}
	off, length, err := sniHostnameSpan(hs)
	if err != nil || length < 4 {
		return nil
	}
	base := recHeaderLen + off
	pts := []int{base + 1, base + length/2, base + length - 1}
	var out []int
	last := 0
	for _, p := range pts {
		if p > last && p < len(payload) {
			out = append(out, p)
			last = p
		}
	}
	return out
}

func fakePacket(tp *tcpPacket, cfg DesyncConfig) OutPacket {
	fakeHS := buildClientHello(cfg.FakeSNI)
	out := make([]byte, tp.dataOff+len(fakeHS))
	copy(out, tp.raw[:tp.dataOff])
	copy(out[tp.dataOff:], fakeHS)
	setIPTotalLen(out)

	op := OutPacket{Data: out}
	for _, f := range cfg.foolings() {
		switch f {
		case FoolTTL:
			ttl := cfg.FakeTTL
			if ttl == 0 {
				ttl = 6
			}
			op.TTL = ttl
		case FoolBadSeq:
			setTCPSeq(out, tp.ihl, tp.seq-66000)
		case FoolDataNoAck:
			clearACKFlag(out, tp.ihl)
		}
	}
	fixChecksums(out, tp.ihl)
	if containsFool(cfg.foolings(), FoolBadSum) {
		op.BadChecksum = true
		corruptTCPChecksum(out, tp.ihl)
	}
	return op
}

func splitPackets(tp *tcpPacket, off int) ([]byte, []byte) {
	payload := tp.payload()
	if off < 1 {
		off = 1
	}
	if off > len(payload)-1 {
		off = len(payload) - 1
	}
	if off < 1 {
		return clone(tp.raw), clone(tp.raw)
	}

	first := make([]byte, tp.dataOff+off)
	copy(first, tp.raw[:tp.dataOff])
	copy(first[tp.dataOff:], payload[:off])
	setIPTotalLen(first)
	fixChecksums(first, tp.ihl)

	second := make([]byte, tp.dataOff+len(payload)-off)
	copy(second, tp.raw[:tp.dataOff])
	copy(second[tp.dataOff:], payload[off:])
	binary.BigEndian.PutUint32(second[tp.ihl+4:tp.ihl+8], tp.seq+uint32(off))
	setIPTotalLen(second)
	fixChecksums(second, tp.ihl)

	return first, second
}

func splitOffset(payload []byte, fallback int) int {
	hs, ok := handshakeBytes(payload)
	if ok {
		if off, length, err := sniHostnameSpan(hs); err == nil && length >= 2 {
			return recHeaderLen + off + length/2
		}
	}
	if fallback < 1 {
		fallback = 2
	}
	return fallback
}

func clone(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func desyncConfigFrom(cfg *Config) DesyncConfig {
	d := defaultDesyncConfig()
	if cfg.DesyncMethod != "" {
		d.Method = DesyncMethod(cfg.DesyncMethod)
	}
	if cfg.DesyncFakeTTL > 0 {
		d.FakeTTL = uint8(cfg.DesyncFakeTTL)
	}
	if cfg.DesyncFakeSNI != "" {
		d.FakeSNI = cfg.DesyncFakeSNI
	}
	d.Foolings = nil
	for _, f := range strings.Fields(cfg.DesyncFooling) {
		d.Foolings = append(d.Foolings, Fooling(f))
	}
	if len(d.Foolings) == 0 {
		d.Foolings = []Fooling{FoolBadSum}
	}
	d.BadSum = false
	return d
}

type desyncStopper interface {
	Status() string
	Stop() error
}
