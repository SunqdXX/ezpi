package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type halfCloser interface{ CloseWrite() error }

type DialFunc func(addr string) (net.Conn, error)

type RelayOpts struct {
	Handshake time.Duration
	Probe     time.Duration
	Idle      time.Duration
}

func (o RelayOpts) withDefaults() RelayOpts {
	if o.Handshake <= 0 {
		o.Handshake = 5 * time.Second
	}
	if o.Probe <= 0 {
		o.Probe = 3 * time.Second
	}
	if o.Idle <= 0 {
		o.Idle = 10 * time.Minute
	}
	return o
}

func readFirstRecord(c net.Conn, timeout time.Duration) (rec []byte, isTLS bool, err error) {
	if err = c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, false, err
	}
	defer c.SetReadDeadline(time.Time{})

	hdr := make([]byte, recHeaderLen)
	if _, err = io.ReadFull(c, hdr); err != nil {
		return nil, false, err
	}
	if hdr[0] != recHandshake {
		return hdr, false, nil
	}
	plen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if plen == 0 || plen > maxRecord {
		return hdr, false, nil
	}
	buf := make([]byte, recHeaderLen+plen)
	copy(buf, hdr)
	if _, err = io.ReadFull(c, buf[recHeaderLen:]); err != nil {
		return buf[:recHeaderLen], false, err
	}
	return buf, true, nil
}

func openUpstream(dst string, dial DialFunc, rec []byte, isTLS bool,
	strats []Strategy, opts RelayOpts) (net.Conn, []byte, Strategy, error) {

	if !isTLS || len(strats) == 0 {
		up, err := dial(dst)
		if err != nil {
			return nil, nil, Strategy{}, err
		}
		if len(rec) > 0 {
			if _, err := up.Write(rec); err != nil {
				up.Close()
				return nil, nil, Strategy{}, err
			}
		}
		return up, nil, Strategy{}, nil
	}

	sni := sniFromRecord(rec)
	target := resolveTarget(dst, sni)
	order := preferCached(strats, sni)

	addrs := []string{target}
	if target != dst {
		addrs = append(addrs, dst)
	}

	type reply struct {
		up    net.Conn
		first []byte
		err   error
		s     Strategy
	}
	replies := make(chan reply, len(order))
	var started []net.Conn
	waiting := 0
	var lastErr error

	await := func(d time.Duration) (reply, bool) {
		timer := time.NewTimer(d)
		defer timer.Stop()
		for waiting > 0 {
			select {
			case r := <-replies:
				waiting--
				if len(r.first) > 0 {
					return r, true
				}
				r.up.Close()
				lastErr = r.err
			case <-timer.C:
				return reply{}, false
			}
		}
		return reply{}, false
	}
	win := func(r reply) (net.Conn, []byte, Strategy, error) {
		for _, c := range started {
			if c != r.up {
				c.Close()
			}
		}
		if sni != "" {
			strategyCache.Store(sni, r.s.Name)
		}
		return r.up, r.first, r.s, nil
	}

	for _, s := range order {
		up, addr, err := dialFirst(dial, addrs)
		if err != nil {
			lastErr = err
			break
		}
		if addr != addrs[0] {
			addrs = []string{addr}
		}
		if err := s.Apply(up, rec); err != nil {
			if _, werr := up.Write(rec); werr != nil {
				up.Close()
				lastErr = werr
				continue
			}
		}
		started = append(started, up)
		waiting++
		go func(up net.Conn, s Strategy) {
			buf := make([]byte, 4096)
			n, err := up.Read(buf)
			if n == 0 && err == nil {
				err = errors.New("server closed without replying")
			}
			replies <- reply{up, buf[:n], err, s}
		}(up, s)

		if r, ok := await(opts.Probe); ok {
			return win(r)
		}
	}
	if r, ok := await(finalWait); ok {
		return win(r)
	}
	for _, c := range started {
		c.Close()
	}
	if lastErr == nil {
		lastErr = errors.New("no strategy produced a reply")
	}
	return nil, nil, Strategy{}, lastErr
}

const finalWait = 8 * time.Second

type ipLookup interface {
	LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error)
}

var proxyResolver ipLookup

var swapAddr func(netip.Addr) bool

func resolveTarget(dst, sni string) string {
	if sni == "" || proxyResolver == nil {
		return dst
	}
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		return dst
	}
	if swapAddr != nil {
		ip, err := netip.ParseAddr(host)
		if err != nil || !swapAddr(ip.Unmap()) {
			return dst
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := proxyResolver.LookupIPv4(ctx, sni)
	if err != nil || len(addrs) == 0 {
		return dst
	}
	for _, a := range addrs {
		if a.String() == host {
			return dst
		}
	}
	return net.JoinHostPort(addrs[0].String(), port)
}

func dialFirst(dial DialFunc, addrs []string) (net.Conn, string, error) {
	var err error
	for _, a := range addrs {
		var c net.Conn
		if c, err = dial(a); err == nil {
			return c, a, nil
		}
	}
	return nil, "", err
}

var strategyCache sync.Map

func sniFromRecord(rec []byte) string {
	_, hs, err := splitHandshake(rec)
	if err != nil {
		return ""
	}
	off, length, err := sniHostnameSpan(hs)
	if err != nil {
		return ""
	}
	return string(hs[off : off+length])
}

func preferCached(strats []Strategy, sni string) []Strategy {
	if sni == "" {
		return strats
	}
	v, ok := strategyCache.Load(sni)
	if !ok {
		return strats
	}
	name, _ := v.(string)
	idx := -1
	for i, s := range strats {
		if s.Name == name {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return strats
	}
	out := make([]Strategy, 0, len(strats))
	out = append(out, strats[idx])
	out = append(out, strats[:idx]...)
	out = append(out, strats[idx+1:]...)
	return out
}

func Relay(client net.Conn, dst string, dial DialFunc, strats []Strategy, opts RelayOpts) error {
	opts = opts.withDefaults()

	rec, isTLS, err := readFirstRecord(client, opts.Handshake)
	if err != nil && !errors.Is(err, io.EOF) && !isTimeout(err) && len(rec) == 0 {
		return err
	}

	up, early, _, err := openUpstream(dst, dial, rec, isTLS, strats, opts)
	if err != nil {
		return err
	}
	defer up.Close()

	if len(early) > 0 {
		if _, err := client.Write(early); err != nil {
			return err
		}
	}

	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(up, client, &last) }()
	go func() { defer wg.Done(); pipe(client, up, &last) }()
	go func() { wg.Wait(); close(done) }()

	tick := min(max(opts.Idle/4, time.Millisecond), 15*time.Second)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-t.C:
			if time.Since(time.Unix(0, last.Load())) >= opts.Idle {
				client.Close()
				up.Close()
				<-done
				return nil
			}
		}
	}
}

func pipe(dst, src net.Conn, last *atomic.Int64) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			last.Store(time.Now().UnixNano())
			if _, werr := dst.Write(buf[:n]); werr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if hc, ok := dst.(halfCloser); ok {
		hc.CloseWrite()
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
