package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
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
		o.Idle = 3 * time.Minute
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

	var lastErr error
	for i, s := range order {
		up, err := dial(target)
		if err != nil {
			lastErr = err
			continue
		}
		if err := s.Apply(up, rec); err != nil {
			if _, werr := up.Write(rec); werr != nil {
				up.Close()
				lastErr = werr
				continue
			}
		}

		if i == len(order)-1 {
			return up, nil, s, nil
		}

		up.SetReadDeadline(time.Now().Add(opts.Probe))
		buf := make([]byte, 4096)
		n, rerr := up.Read(buf)
		up.SetReadDeadline(time.Time{})
		if rerr == nil && n > 0 {
			if sni != "" {
				strategyCache.Store(sni, s.Name)
			}
			return up, buf[:n], s, nil
		}
		up.Close()
		if rerr == nil {
			rerr = errors.New("server closed without replying")
		}
		lastErr = rerr
	}
	if lastErr == nil {
		lastErr = errors.New("no strategy produced a reply")
	}
	return nil, nil, Strategy{}, lastErr
}

var proxyResolver *Resolver

func resolveTarget(dst, sni string) string {
	if sni == "" || proxyResolver == nil {
		return dst
	}
	_, port, err := net.SplitHostPort(dst)
	if err != nil {
		return dst
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := proxyResolver.LookupIPv4(ctx, sni)
	if err != nil || len(addrs) == 0 {
		return dst
	}
	return net.JoinHostPort(addrs[0].String(), port)
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

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(up, client, opts.Idle) }()
	go func() { defer wg.Done(); pipe(client, up, opts.Idle) }()
	wg.Wait()
	return nil
}

func pipe(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		if err := src.SetReadDeadline(time.Now().Add(idle)); err != nil {
			break
		}
		n, rerr := src.Read(buf)
		if n > 0 {
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
