package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func streamingServer(t *testing.T, total time.Duration) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Read(make([]byte, 64))
		gone := make(chan struct{})
		go func() { io.Copy(io.Discard, c); close(gone) }()
		end := time.Now().Add(total)
		for time.Now().Before(end) {
			select {
			case <-gone:
				return
			case <-time.After(40 * time.Millisecond):
			}
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
		}
		c.Write([]byte("END"))
	}()
	return ln
}

func TestRelayKeepsOneWayStreamAlive(t *testing.T) {
	ln := streamingServer(t, 1500*time.Millisecond)
	defer ln.Close()

	a, b := net.Pipe()
	defer a.Close()
	dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
	go Relay(b, ln.Addr().String(), dial, nil,
		RelayOpts{Handshake: time.Second, Idle: 300 * time.Millisecond})
	go a.Write([]byte("POST /v1/messages HTTP/1.1\r\n\r\n"))

	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(a)
	if !strings.HasSuffix(string(got), "END") {
		t.Fatalf("stream was cut after %d bytes: a silent client must not count as idle while the server is still sending", len(got))
	}
}

func TestRelayClosesWhenBothSidesIdle(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c)
	}()

	a, b := net.Pipe()
	defer a.Close()
	dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
	done := make(chan struct{})
	go func() {
		Relay(b, ln.Addr().String(), dial, nil,
			RelayOpts{Handshake: time.Second, Idle: 200 * time.Millisecond})
		close(done)
	}()
	go a.Write([]byte("hello there\r\n"))
	go io.Copy(io.Discard, a)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay stayed open although both sides were silent past the idle timeout")
	}
}

func TestRelayDialFailureDoesNotRetryEveryStrategy(t *testing.T) {
	rec := realClientHello(t, "api.example.com")
	var calls atomic.Int32
	dial := func(addr string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("i/o timeout")
	}
	a, b := net.Pipe()
	defer a.Close()
	go a.Write(rec)
	err := Relay(b, "192.0.2.1:443", dial, Strategies, RelayOpts{Handshake: time.Second})
	if err == nil {
		t.Fatal("expected an error")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("dialled %d times for one unreachable address; a failed connect is not fixed by another split", n)
	}
}

func TestDialFirstFallsBackToNextAddress(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	good := ln.Addr().String()
	dial := func(addr string) (net.Conn, error) {
		if addr != good {
			return nil, errors.New("i/o timeout")
		}
		return net.Dial("tcp", addr)
	}
	c, addr, err := dialFirst(dial, []string{"192.0.2.1:443", good})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if addr != good {
		t.Fatalf("used %s, want %s", addr, good)
	}
}

func tlsUpstream(t *testing.T, reply func(i int32, c net.Conn)) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			i := n.Add(1)
			go func() {
				defer c.Close()
				c.Read(make([]byte, 16384))
				reply(i, c)
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln
}

func relayFirstReply(t *testing.T, ln net.Listener, probe time.Duration) string {
	t.Helper()
	rec := realClientHello(t, "slow.example.com")
	a, b := net.Pipe()
	defer a.Close()
	dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
	go a.Write(rec)
	go Relay(b, ln.Addr().String(), dial, Strategies[:3],
		RelayOpts{Handshake: time.Second, Probe: probe})
	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _ := a.Read(buf)
	return string(buf[:n])
}

func TestRelayDoesNotKillASlowServer(t *testing.T) {
	ln := tlsUpstream(t, func(i int32, c net.Conn) {
		if i == 1 {
			time.Sleep(700 * time.Millisecond)
			c.Write([]byte("first"))
		}
	})
	defer ln.Close()
	if got := relayFirstReply(t, ln, 200*time.Millisecond); got != "first" {
		t.Fatalf("got %q: a server that answers after the probe time must still win", got)
	}
}

func TestRelayMovesPastABlackholedAttempt(t *testing.T) {
	ln := tlsUpstream(t, func(i int32, c net.Conn) {
		if i == 2 {
			c.Write([]byte("second"))
		}
	})
	defer ln.Close()
	if got := relayFirstReply(t, ln, 200*time.Millisecond); got != "second" {
		t.Fatalf("got %q, want the answer from the second strategy", got)
	}
}

type stubLookup []netip.Addr

func (s stubLookup) LookupIPv4(context.Context, string) ([]netip.Addr, error) { return s, nil }

func TestResolveTargetKeepsTheAppsAddressUnlessItIsABlockPage(t *testing.T) {
	oldR, oldS := proxyResolver, swapAddr
	defer func() { proxyResolver, swapAddr = oldR, oldS }()
	proxyResolver = stubLookup{netip.MustParseAddr("203.0.113.7")}
	block := netip.MustParseAddr("195.175.254.2")
	swapAddr = func(ip netip.Addr) bool { return ip == block }

	if got := resolveTarget("198.51.100.9:443", "cdn.example.com"); got != "198.51.100.9:443" {
		t.Fatalf("unblocked site moved to %s; the app's own CDN address must be kept", got)
	}
	if got := resolveTarget("195.175.254.2:443", "discord.com"); got != "203.0.113.7:443" {
		t.Fatalf("block-page address kept (%s); it must be replaced by the real one", got)
	}
	swapAddr = nil
	if got := resolveTarget("198.51.100.9:443", "cdn.example.com"); got != "203.0.113.7:443" {
		t.Fatalf("with no policy (Android) every name must use DoH, got %s", got)
	}
}
