package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type ProbeResult struct {
	Host       string `json:"host"`
	OK         bool   `json:"ok"`
	Millis     int64  `json:"ms"`
	Issuer     string `json:"issuer,omitempty"`
	Error      string `json:"error,omitempty"`
	DNSMillis  int64  `json:"dns_ms"`
	EngineDown bool   `json:"engine_down,omitempty"`
	DNSFailed  bool   `json:"dns_failed,omitempty"`
}

type SelfTest struct {
	Version string `json:"version"`
	Method  string `json:"method"`

	OK         bool          `json:"ok"`
	Results    []ProbeResult `json:"results"`
	Via        string        `json:"via"`
	Conclusive bool          `json:"conclusive"`
	Note       string        `json:"note,omitempty"`
}

func RunSelfTest(cfg *Config) SelfTest {
	hosts := cfg.SelfTestHosts
	timeout := cfg.HandshakeTimeout()
	skipIfaces := cfg.SkipInterfaces
	out := make([]ProbeResult, len(hosts))

	addrs := make([][]netip.Addr, len(hosts))
	dnsMillis := make([]int64, len(hosts))
	dnsErrs := make([]error, len(hosts))
	var rwg sync.WaitGroup
	for i, host := range hosts {
		rwg.Add(1)
		go func(i int, host string) {
			defer rwg.Done()
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), timeout+8*time.Second)
			a, _, err := bootstrapResolve(ctx, &net.Dialer{Timeout: timeout}, host)
			cancel()
			addrs[i], dnsMillis[i], dnsErrs[i] = a, time.Since(start).Milliseconds(), err
		}(i, host)
	}
	rwg.Wait()

	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			out[i] = probeResolved(cfg, host, addrs[i], dnsMillis[i], dnsErrs[i], timeout)
		}(i, h)
	}
	wg.Wait()

	st := SelfTest{Version: Version, Method: activeMethod(), OK: true, Results: out, Conclusive: true}
	for _, r := range out {
		if !r.OK {
			st.OK = false
		}
	}

	st.Via = egressInterface()
	for _, skip := range skipIfaces {
		if st.Via == skip {
			st.Conclusive = false
			st.Note = fmt.Sprintf("traffic left via %s, which EzPi deliberately does not touch; "+
				"this proves the sites are reachable, not that the bypass works", st.Via)
		}
	}
	return st
}

func egressInterface() string {
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ""
	}
	return interfaceForIP(host)
}

func interfaceForIP(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, in := range ifaces {
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.String() == ip {
				return in.Name
			}
		}
	}
	return ""
}

func probeResolved(cfg *Config, host string, addrs []netip.Addr, dnsMillis int64, dnsErr error, timeout time.Duration) ProbeResult {
	r := ProbeResult{Host: host, DNSMillis: dnsMillis}

	if dnsErr != nil || len(addrs) == 0 {
		r.Millis = dnsMillis
		r.DNSFailed = true
		if dnsErr != nil {
			r.Error = "dns lookup failed: " + dnsErr.Error()
		} else {
			r.Error = "dns lookup returned no addresses"
		}
		return r
	}

	connectStart := time.Now()
	raw, err := selfTestDial(cfg, host, net.JoinHostPort(addrs[0].String(), "443"), timeout)
	if err != nil {
		r.Millis = time.Since(connectStart).Milliseconds()
		r.Error = err.Error()
		r.EngineDown = looksLikeEngineDown(err)
		return r
	}
	raw.SetDeadline(time.Now().Add(timeout))

	conn := tls.Client(raw, &tls.Config{ServerName: host})
	err = conn.Handshake()
	r.Millis = time.Since(connectStart).Milliseconds()
	if err != nil {
		raw.Close()
		r.Error = err.Error()
		return r
	}
	raw.SetDeadline(time.Time{})
	defer conn.Close()

	if cs := conn.ConnectionState(); len(cs.PeerCertificates) > 0 {
		r.Issuer = cs.PeerCertificates[0].Issuer.CommonName
	}
	r.OK = true
	return r
}

func looksLikeEngineDown(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, sign := range []string{
		"does not seem to be running", "connection refused", "refused connect",
		"did not answer connect", "actively refused", "eof",
	} {
		if strings.Contains(msg, sign) {
			return true
		}
	}
	return false
}

func writeSelfTest(w io.Writer, st SelfTest, asJSON bool) {
	if !asJSON {
		fmt.Fprintf(w, "EzPi %s on %s (%s)\n\n", st.Version, platformName, st.Method)
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(st)
		return
	}
	dnsTrouble := false
	for _, r := range st.Results {
		switch {
		case r.OK:
			fmt.Fprintf(w, "  OK      %-24s %4dms  cert issued by %s\n", r.Host, r.Millis, r.Issuer)
		case r.EngineDown:
			fmt.Fprintf(w, "  ENGINE  %-24s %4dms  %s\n", r.Host, r.Millis, r.Error)
		case r.DNSFailed:
			dnsTrouble = true
			fmt.Fprintf(w, "  DNS     %-24s %4dms  %s\n", r.Host, r.Millis, r.Error)
		default:
			fmt.Fprintf(w, "  BLOCKED %-24s %4dms  %s\n", r.Host, r.Millis, r.Error)
		}
	}
	engineDown := false
	for _, r := range st.Results {
		if r.EngineDown {
			engineDown = true
		}
	}
	if engineDown {
		fmt.Fprintln(w, "\nEzPi's own engine did not answer, so this says nothing about your")
		fmt.Fprintln(w, "provider. Antivirus software blocking or removing EzPi is the usual cause.")
	}
	if dnsTrouble {
		fmt.Fprintln(w, "\nname resolution failed, so nothing was learned about the bypass")
	}
	switch {
	case !st.Conclusive:
		fmt.Fprintf(w, "\nINCONCLUSIVE: %s\n", st.Note)
	case st.OK:
		fmt.Fprintf(w, "\nbypass verified working (via %s)\n", st.Via)
	default:
		fmt.Fprintf(w, "\nbypass NOT working (via %s)\n", st.Via)
	}
}
