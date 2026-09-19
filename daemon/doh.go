package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type dohEndpoint struct {
	addr string
	host string
	path string
}

var defaultDoH = []dohEndpoint{
	{addr: "1.1.1.1:443", host: "cloudflare-dns.com", path: "/dns-query"},
	{addr: "8.8.8.8:443", host: "dns.google", path: "/dns-query"},
	{addr: "9.9.9.9:443", host: "dns.quad9.net", path: "/dns-query"},
}

type dnsCacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

type Resolver struct {
	endpoints []dohEndpoint
	dialer    *net.Dialer
	strat     Strategy
	ttl       time.Duration

	mu       sync.Mutex
	cache    map[string]dnsCacheEntry
	inFlight map[string]*pendingLookup

	clientMu sync.Mutex
	clients  map[string]*http.Client
}

type pendingLookup struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

func NewResolver(dialer *net.Dialer, strat Strategy) *Resolver {
	return &Resolver{
		endpoints: defaultDoH,
		dialer:    dialer,
		strat:     strat,
		ttl:       5 * time.Minute,
		cache:     make(map[string]dnsCacheEntry),
		inFlight:  make(map[string]*pendingLookup),
		clients:   make(map[string]*http.Client),
	}
}

func (r *Resolver) client(ep dohEndpoint) *http.Client {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	if c, ok := r.clients[ep.addr]; ok {
		return c
	}
	c := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return DialTLSWithStrategy(ctx, r.dialer, ep.addr, ep.host, r.strat)
			},
		},
	}
	r.clients[ep.addr] = c
	return c
}

func (r *Resolver) Close() {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()
	for _, c := range r.clients {
		if t, ok := c.Transport.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}

func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}

	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.addrs, nil
	}
	if p, ok := r.inFlight[host]; ok {
		r.mu.Unlock()
		select {
		case <-p.done:
			return p.addrs, p.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	pending := &pendingLookup{done: make(chan struct{})}
	r.inFlight[host] = pending
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.inFlight, host)
		r.mu.Unlock()
		close(pending.done)
	}()

	type result struct {
		addrs []netip.Addr
		err   error
	}
	raceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	results := make(chan result, len(r.endpoints))
	for _, ep := range r.endpoints {
		go func(ep dohEndpoint) {
			addrs, err := r.query(raceCtx, ep, host)
			if err == nil && len(addrs) == 0 {
				err = fmt.Errorf("%s: no A records", ep.host)
			}
			results <- result{addrs, err}
		}(ep)
	}

	var lastErr error
	for range r.endpoints {
		res := <-results
		if res.err == nil && len(res.addrs) > 0 {
			r.mu.Lock()
			r.cache[host] = dnsCacheEntry{addrs: res.addrs, expires: time.Now().Add(r.ttl)}
			r.mu.Unlock()
			pending.addrs = res.addrs
			return res.addrs, nil
		}
		lastErr = res.err
	}
	if lastErr == nil {
		lastErr = errors.New("no DoH endpoints answered")
	}
	pending.err = lastErr
	return nil, lastErr
}

func (r *Resolver) query(ctx context.Context, ep dohEndpoint, host string) ([]netip.Addr, error) {
	msg, err := buildDNSQuery(host)
	if err != nil {
		return nil, err
	}

	client := r.client(ep)

	url := "https://" + ep.host + ep.path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", ep.host, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseDNSAnswers(body)
}

func buildDNSQuery(host string) ([]byte, error) {
	var b bytes.Buffer
	b.Write(binary.BigEndian.AppendUint16(nil, uint16(rand.Intn(1<<16))))
	b.Write([]byte{0x01, 0x00})
	b.Write([]byte{0x00, 0x01})
	b.Write(make([]byte, 6))
	for _, label := range splitLabels(host) {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid hostname %q", host)
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	b.Write([]byte{0x00, 0x01, 0x00, 0x01})
	return b.Bytes(), nil
}

func splitLabels(host string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(host); i++ {
		if i == len(host) || host[i] == '.' {
			if i > start {
				out = append(out, host[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func parseDNSAnswers(msg []byte) ([]netip.Addr, error) {
	if len(msg) < 12 {
		return nil, errors.New("DNS reply too short")
	}
	if rcode := msg[3] & 0x0f; rcode != 0 {
		return nil, fmt.Errorf("DNS rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	an := int(binary.BigEndian.Uint16(msg[6:]))

	off := 12
	skipName := func(o int) (int, error) {
		for {
			if o >= len(msg) {
				return 0, errors.New("name runs past end of message")
			}
			l := msg[o]
			if l&0xC0 == 0xC0 {
				return o + 2, nil
			}
			o++
			if l == 0 {
				return o, nil
			}
			o += int(l)
		}
	}
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(off); err != nil {
			return nil, err
		}
		off += 4
	}

	var out []netip.Addr
	for i := 0; i < an; i++ {
		if off, err = skipName(off); err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("truncated answer header")
		}
		typ := binary.BigEndian.Uint16(msg[off:])
		dlen := int(binary.BigEndian.Uint16(msg[off+8:]))
		off += 10
		if off+dlen > len(msg) {
			return nil, errors.New("answer overruns message")
		}
		if typ == 1 && dlen == 4 {
			out = append(out, netip.AddrFrom4([4]byte(msg[off:off+4])))
		}
		off += dlen
	}
	return out, nil
}
