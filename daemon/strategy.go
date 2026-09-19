package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	recHandshake  = 0x16
	hsClientHello = 0x01
	extServerName = 0x0000

	recHeaderLen = 5
	maxRecord    = 16384
)

var errNotClientHello = errors.New("not a TLS ClientHello record")

type step struct {
	data  []byte
	pause time.Duration
}

type Strategy struct {
	Name  string
	Short string

	Defeats string

	build func(rec []byte) ([]step, error)
}

var sleepFn = time.Sleep

func (s Strategy) Apply(w io.Writer, rec []byte) error {
	steps, err := s.build(rec)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if _, err := w.Write(st.data); err != nil {
			return err
		}
		if st.pause > 0 {
			sleepFn(st.pause)
		}
	}
	return nil
}

func sniHostnameSpan(hs []byte) (off, length int, err error) {
	if len(hs) < 4 || hs[0] != hsClientHello {
		return 0, 0, errNotClientHello
	}
	body := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if body+4 > len(hs) {
		return 0, 0, fmt.Errorf("handshake truncated: says %d, have %d", body, len(hs)-4)
	}
	p := 4
	p += 2 + 32
	if p >= len(hs) {
		return 0, 0, errors.New("truncated before session id")
	}
	p += 1 + int(hs[p])
	if p+2 > len(hs) {
		return 0, 0, errors.New("truncated before cipher suites")
	}
	p += 2 + int(binary.BigEndian.Uint16(hs[p:]))
	if p >= len(hs) {
		return 0, 0, errors.New("truncated before compression")
	}
	p += 1 + int(hs[p])
	if p+2 > len(hs) {
		return 0, 0, errors.New("no extensions present")
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(hs[p:]))
	p += 2
	if extEnd > len(hs) {
		return 0, 0, errors.New("extensions overrun record")
	}

	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(hs[p:])
		elen := int(binary.BigEndian.Uint16(hs[p+2:]))
		data := p + 4
		if data+elen > extEnd {
			return 0, 0, errors.New("extension overruns list")
		}
		if etype == extServerName {
			q := data
			if q+2 > data+elen {
				return 0, 0, errors.New("malformed SNI extension")
			}
			q += 2
			for q+3 <= data+elen {
				ntype := hs[q]
				nlen := int(binary.BigEndian.Uint16(hs[q+1:]))
				host := q + 3
				if host+nlen > data+elen {
					return 0, 0, errors.New("SNI entry overruns extension")
				}
				if ntype == 0 && nlen > 0 {
					return host, nlen, nil
				}
				q = host + nlen
			}
			return 0, 0, errors.New("SNI extension has no host_name")
		}
		p = data + elen
	}
	return 0, 0, errors.New("no SNI extension")
}

func splitHandshake(rec []byte) (ver []byte, hs []byte, err error) {
	if len(rec) < recHeaderLen || rec[0] != recHandshake {
		return nil, nil, errNotClientHello
	}
	plen := int(binary.BigEndian.Uint16(rec[3:5]))
	if plen+recHeaderLen != len(rec) {
		return nil, nil, fmt.Errorf("record length %d does not match buffer %d", plen, len(rec)-recHeaderLen)
	}
	hs = rec[recHeaderLen:]
	if len(hs) < 2 || hs[0] != hsClientHello {
		return nil, nil, errNotClientHello
	}
	return rec[1:3], hs, nil
}

func midSNI(hs []byte, fallback int) int {
	clamp := func(n int) int {
		if n < 1 {
			return 1
		}
		if n > len(hs)-1 {
			return len(hs) - 1
		}
		return n
	}
	off, length, err := sniHostnameSpan(hs)
	if err != nil {
		return clamp(fallback)
	}
	if length == 1 {
		return clamp(off)
	}
	return clamp(off + length/2)
}

func record(ver, payload []byte) []byte {
	out := make([]byte, 0, recHeaderLen+len(payload))
	out = append(out, recHandshake, ver[0], ver[1])
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	return append(out, payload...)
}

var Strategies = []Strategy{
	{
		Name:    "record-sni",
		Defeats: "record",
		Short:   "split into two TLS records inside the hostname",
		build: func(rec []byte) ([]step, error) {
			ver, hs, err := splitHandshake(rec)
			if err != nil {
				return nil, err
			}
			n := midSNI(hs, 1)
			out := append(record(ver, hs[:n]), record(ver, hs[n:])...)
			return []step{{data: out}}, nil
		},
	},
	{
		Name:    "record-tiny",
		Defeats: "record",
		Short:   "two TLS records, the first only one byte",
		build: func(rec []byte) ([]step, error) {
			ver, hs, err := splitHandshake(rec)
			if err != nil {
				return nil, err
			}
			out := append(record(ver, hs[:1]), record(ver, hs[1:])...)
			return []step{{data: out}}, nil
		},
	},
	{
		Name:    "record-multi",
		Defeats: "record",
		Short:   "three TLS records across the hostname",
		build: func(rec []byte) ([]step, error) {
			ver, hs, err := splitHandshake(rec)
			if err != nil {
				return nil, err
			}
			off, length, err := sniHostnameSpan(hs)
			a, b := 1, len(hs)/2
			if err == nil && length >= 2 {
				a, b = off, off+length/2
				if a < 1 {
					a = 1
				}
			}
			if b <= a {
				b = a + 1
			}
			if b >= len(hs) {
				b = len(hs) - 1
			}
			if a >= b {
				a = b - 1
			}
			if a < 1 {
				return nil, errors.New("ClientHello too small to split three ways")
			}
			out := record(ver, hs[:a])
			out = append(out, record(ver, hs[a:b])...)
			out = append(out, record(ver, hs[b:])...)
			return []step{{data: out}}, nil
		},
	},
	{
		Name:    "tcp-sni",
		Defeats: "packet",
		Short:   "one record sent as two TCP packets, split inside the hostname",
		build: func(rec []byte) ([]step, error) {
			_, hs, err := splitHandshake(rec)
			if err != nil {
				return nil, err
			}
			n := recHeaderLen + midSNI(hs, 1)
			return []step{
				{data: rec[:n], pause: 12 * time.Millisecond},
				{data: rec[n:]},
			}, nil
		},
	},
	{
		Name:    "tcp-tiny",
		Defeats: "packet",
		Short:   "one record sent as two TCP packets, the first tiny",
		build: func(rec []byte) ([]step, error) {
			if len(rec) < recHeaderLen+2 {
				return nil, errNotClientHello
			}
			return []step{
				{data: rec[:recHeaderLen+1], pause: 12 * time.Millisecond},
				{data: rec[recHeaderLen+1:]},
			}, nil
		},
	},
	{
		Name:    "record-sni+tcp",
		Defeats: "both",
		Short:   "two TLS records, each in its own TCP packet",
		build: func(rec []byte) ([]step, error) {
			ver, hs, err := splitHandshake(rec)
			if err != nil {
				return nil, err
			}
			n := midSNI(hs, 1)
			return []step{
				{data: record(ver, hs[:n]), pause: 12 * time.Millisecond},
				{data: record(ver, hs[n:])},
			}, nil
		},
	},
	{
		Name:    "record-sni-slow",
		Defeats: "both",
		Short:   "two TLS records a second apart, for slow reassembly windows",
		build: func(rec []byte) ([]step, error) {
			ver, hs, err := splitHandshake(rec)
			if err != nil {
				return nil, err
			}
			n := midSNI(hs, 1)
			return []step{
				{data: record(ver, hs[:n]), pause: 250 * time.Millisecond},
				{data: record(ver, hs[n:])},
			}, nil
		},
	},
	{
		Name:    "none",
		Defeats: "",
		Short:   "no modification (control, and for unblocked connections)",
		build: func(rec []byte) ([]step, error) {
			return []step{{data: rec}}, nil
		},
	},
}

func (s Strategy) AddedLatency() time.Duration {
	steps, err := s.build(sampleClientHello())
	if err != nil {
		return 0
	}
	var total time.Duration
	for _, st := range steps {
		total += st.pause
	}
	return total
}

func sampleClientHello() []byte {
	host := []byte("example.com")
	sn := append([]byte{0x00}, byte(len(host)>>8), byte(len(host)))
	sn = append(sn, host...)
	sl := append([]byte{byte(len(sn) >> 8), byte(len(sn))}, sn...)
	ext := append([]byte{0x00, 0x00, byte(len(sl) >> 8), byte(len(sl))}, sl...)

	body := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := append([]byte{hsClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return record([]byte{0x03, 0x01}, hs)
}

func StrategyByName(name string) (Strategy, bool) {
	for _, s := range Strategies {
		if s.Name == name {
			return s, true
		}
	}
	return Strategy{}, false
}

func StrategyNames() []string {
	out := make([]string, 0, len(Strategies))
	for _, s := range Strategies {
		out = append(out, s.Name)
	}
	return out
}
