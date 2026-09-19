package engine

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func realClientHello(t *testing.T, host string) []byte {
	t.Helper()
	c, s := net.Pipe()
	go func() {
		tls.Client(c, &tls.Config{ServerName: host}).Handshake()
		c.Close()
	}()
	defer s.Close()
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, recHeaderLen)
	if _, err := io.ReadFull(s, hdr); err != nil {
		t.Fatalf("reading record header: %v", err)
	}
	rec := make([]byte, recHeaderLen+int(binary.BigEndian.Uint16(hdr[3:5])))
	copy(rec, hdr)
	if _, err := io.ReadFull(s, rec[recHeaderLen:]); err != nil {
		t.Fatalf("reading record body: %v", err)
	}
	return rec
}

func reassemble(t *testing.T, wire []byte) []byte {
	t.Helper()
	var out []byte
	for p := 0; p < len(wire); {
		if p+recHeaderLen > len(wire) {
			t.Fatalf("truncated record header at %d", p)
		}
		if wire[p] != recHandshake {
			t.Fatalf("record at %d has type 0x%02x, want 0x16", p, wire[p])
		}
		n := int(binary.BigEndian.Uint16(wire[p+3 : p+5]))
		if p+recHeaderLen+n > len(wire) {
			t.Fatalf("record at %d overruns buffer", p)
		}
		out = append(out, wire[p+recHeaderLen:p+recHeaderLen+n]...)
		p += recHeaderLen + n
	}
	return out
}

func TestMain(m *testing.M) {
	sleepFn = func(time.Duration) {}
	os.Exit(m.Run())
}

func TestSNIHostnameSpanFindsTheName(t *testing.T) {
	for _, host := range []string{"discord.com", "gateway.discord.gg", "a.io", "www.roblox.com"} {
		rec := realClientHello(t, host)
		off, n, err := sniHostnameSpan(rec[recHeaderLen:])
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got := string(rec[recHeaderLen+off : recHeaderLen+off+n]); got != host {
			t.Errorf("located %q, want %q", got, host)
		}
	}
}

func TestEveryStrategyPreservesBytes(t *testing.T) {
	for _, host := range []string{"gateway.discord.gg", "www.roblox.com", "a.io"} {
		rec := realClientHello(t, host)
		want := rec[recHeaderLen:]
		for _, s := range Strategies {
			t.Run(s.Name+"/"+host, func(t *testing.T) {
				var buf bytes.Buffer
				if err := s.Apply(&buf, rec); err != nil {
					t.Fatalf("apply: %v", err)
				}
				if got := reassemble(t, buf.Bytes()); !bytes.Equal(got, want) {
					t.Fatalf("reassembled handshake differs from the original")
				}
			})
		}
	}
}

func TestEveryStrategyHidesHostname(t *testing.T) {
	const host = "gateway.discord.gg"
	rec := realClientHello(t, host)

	firstRecord := func(wire []byte) []byte {
		if len(wire) < recHeaderLen {
			return wire
		}
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if recHeaderLen+n > len(wire) {
			return wire
		}
		return wire[:recHeaderLen+n]
	}

	for _, s := range Strategies {
		t.Run(s.Name, func(t *testing.T) {
			steps, err := s.build(rec)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if len(steps) == 0 {
				t.Fatal("produced no writes")
			}
			var all []byte
			for _, st := range steps {
				all = append(all, st.data...)
			}

			if s.Name == "none" {
				if s.Defeats != "" {
					t.Errorf("the control strategy claims to defeat %q", s.Defeats)
				}
				return
			}

			checkPacket := s.Defeats == "packet" || s.Defeats == "both"
			checkRecord := s.Defeats == "record" || s.Defeats == "both"
			if !checkPacket && !checkRecord {
				t.Fatalf("Defeats = %q, want record, packet or both", s.Defeats)
			}
			if checkPacket && bytes.Contains(steps[0].data, []byte(host)) {
				t.Error("claims to defeat packet-level inspection, but the first packet contains the whole hostname")
			}
			if checkRecord && bytes.Contains(firstRecord(all), []byte(host)) {
				t.Error("claims to defeat record-level inspection, but the first record contains the whole hostname")
			}
			if !bytes.Contains(all, []byte(host[:4])) {
				t.Error("hostname vanished entirely; the split is wrong")
			}
		})
	}
}

func TestCheapStrategiesComeFirst(t *testing.T) {
	var worst time.Duration
	for _, s := range Strategies {
		if s.Name == "none" {
			continue
		}
		lat := s.AddedLatency()
		if lat < worst {
			t.Errorf("%s adds %v but is listed after a slower strategy; "+
				"auto-tuning would pick a more expensive option than it needs",
				s.Name, lat)
		}
		if lat > worst {
			worst = lat
		}
		if lat > 300*time.Millisecond {
			t.Errorf("%s adds %v per connection, which is too slow to ship", s.Name, lat)
		}
	}
}

func TestStrategyNamesAreUniqueAndLookupWorks(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Strategies {
		if seen[s.Name] {
			t.Errorf("duplicate strategy name %q", s.Name)
		}
		seen[s.Name] = true
		if s.Short == "" {
			t.Errorf("%s has no description", s.Name)
		}
		if got, ok := StrategyByName(s.Name); !ok || got.Name != s.Name {
			t.Errorf("StrategyByName(%q) failed", s.Name)
		}
	}
	if _, ok := StrategyByName("does-not-exist"); ok {
		t.Error("StrategyByName invented a strategy")
	}
}

func TestStrategiesSurviveMalformedInput(t *testing.T) {
	cases := [][]byte{
		{}, {0x16}, {0x16, 0x03, 0x01}, {0x16, 0x03, 0x01, 0x00, 0x00},
		{0x16, 0x03, 0x01, 0xff, 0xff, 0x01},
		{0x17, 0x03, 0x03, 0x00, 0x01, 0x41},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0xff, 0xff},
		{0x16, 0x03, 0x01, 0x00, 0x01, 0x01},
	}
	real := realClientHello(t, "discord.com")
	for i := 0; i < len(real); i++ {
		cases = append(cases, real[:i])
	}
	rng := rand.New(rand.NewSource(1))
	buf := make([]byte, 512)
	for i := 0; i < 500; i++ {
		rng.Read(buf)
		cases = append(cases, append([]byte{0x16, 0x03, 0x01}, buf[:rng.Intn(len(buf))]...))
	}

	for _, s := range Strategies {
		for i, c := range cases {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s panicked on case %d: %v", s.Name, i, r)
					}
				}()
				var sink bytes.Buffer
				s.Apply(&sink, c)
				if len(c) > recHeaderLen {
					sniHostnameSpan(c[recHeaderLen:])
				}
			}()
		}
	}
}

func TestRelayCompletesRealHandshakeForEveryStrategy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "through the proxy")
	}))
	defer srv.Close()

	for _, s := range Strategies {
		t.Run(s.Name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
						Relay(c, srv.Listener.Addr().String(), dial,
							[]Strategy{s}, RelayOpts{Handshake: 3 * time.Second})
					}()
				}
			}()

			client := srv.Client()
			client.Transport.(*http.Transport).DialContext = nil
			client.Transport.(*http.Transport).Dial = func(_, _ string) (net.Conn, error) {
				return net.Dial("tcp", ln.Addr().String())
			}
			client.Timeout = 10 * time.Second
			resp, err := client.Get(srv.URL)
			if err != nil {
				t.Fatalf("handshake through relay failed: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "through the proxy" {
				t.Fatalf("got %q", body)
			}
		})
	}
}

func TestRelayPassesThroughNonTLS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- b
	}()

	a, b := net.Pipe()
	strat, _ := StrategyByName("record-sni")
	dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
	go Relay(b, ln.Addr().String(), dial, []Strategy{strat},
		RelayOpts{Handshake: time.Second})
	want := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	a.Write([]byte(want))
	a.Close()

	select {
	case b := <-got:
		if string(b) != want {
			t.Fatalf("got %q, want %q", b, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for passthrough")
	}
}

func TestDNSQueryAndAnswerParsing(t *testing.T) {
	q, err := buildDNSQuery("www.roblox.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(q) < 12+4 {
		t.Fatal("query too short")
	}
	if got := binary.BigEndian.Uint16(q[4:]); got != 1 {
		t.Errorf("qdcount = %d, want 1", got)
	}

	reply := append([]byte{}, q...)
	reply[2] = 0x81
	reply[3] = 0x80
	binary.BigEndian.PutUint16(reply[6:], 1)
	reply = append(reply, 0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c,
		0x00, 0x04, 93, 184, 216, 34)
	addrs, err := parseDNSAnswers(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "93.184.216.34" {
		t.Fatalf("got %v", addrs)
	}

	if _, err := parseDNSAnswers([]byte{0, 1, 2}); err == nil {
		t.Error("accepted a truncated reply")
	}
	bad := append([]byte{}, reply...)
	bad[3] = 0x83
	if _, err := parseDNSAnswers(bad); err == nil {
		t.Error("accepted an NXDOMAIN reply as success")
	}
}

func TestRelayRetriesWhenAStrategyIsBlocked(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "recovered")
	}))
	defer srv.Close()

	var attempts int32
	censor, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer censor.Close()
	go func() {
		for {
			c, err := censor.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if atomic.AddInt32(&attempts, 1) == 1 {
					io.Copy(io.Discard, c)
					c.Close()
					return
				}
				up, err := net.Dial("tcp", srv.Listener.Addr().String())
				if err != nil {
					c.Close()
					return
				}
				go func() { io.Copy(up, c); up.Close() }()
				io.Copy(c, up)
				c.Close()
			}(c)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	strats := []Strategy{Strategies[0], Strategies[1], Strategies[2]}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
				Relay(c, censor.Addr().String(), dial, strats,
					RelayOpts{Handshake: 3 * time.Second, Probe: 700 * time.Millisecond})
			}()
		}
	}()

	client := srv.Client()
	client.Transport.(*http.Transport).DialContext = nil
	client.Transport.(*http.Transport).Dial = func(_, _ string) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	client.Timeout = 15 * time.Second

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("retry did not recover the connection: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "recovered" {
		t.Fatalf("got %q", body)
	}
	if n := atomic.LoadInt32(&attempts); n < 2 {
		t.Errorf("expected a retry, saw %d attempt(s)", n)
	}
}

func TestRelayClosesIdleConnections(t *testing.T) {
	quiet, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()
	go func() {
		for {
			c, err := quiet.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	a, b := net.Pipe()
	defer a.Close()
	done := make(chan struct{})
	go func() {
		dial := func(addr string) (net.Conn, error) { return net.Dial("tcp", addr) }
		Relay(b, quiet.Addr().String(), dial, nil,
			RelayOpts{Handshake: time.Second, Probe: 200 * time.Millisecond,
				Idle: 400 * time.Millisecond})
		close(done)
	}()
	a.Write([]byte("GET / HTTP/1.1\r\n\r\n"))

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("relay held an idle connection open instead of closing it")
	}
}
