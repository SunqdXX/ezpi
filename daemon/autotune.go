package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

type TuneResult struct {
	Strategy string `json:"strategy"`
	OK       bool   `json:"ok"`
	Millis   int64  `json:"ms"`
	Error    string `json:"error,omitempty"`
}

type TuneReport struct {
	Chosen    string       `json:"chosen"`
	ProbeHost string       `json:"probe_host,omitempty"`
	Blocked   bool         `json:"blocked"`
	AllFailed bool         `json:"all_failed"`
	DNSVia    string       `json:"dns_via,omitempty"`
	Results   []TuneResult `json:"results"`
	Note      string       `json:"note,omitempty"`
}

var (
	resolverMu   sync.Mutex
	sharedRes    *Resolver
	sharedResVia string
)

func cachedResolver() (*Resolver, string) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	return sharedRes, sharedResVia
}

func setCachedResolver(r *Resolver, via string) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	sharedRes, sharedResVia = r, via
}

func bootstrapResolve(ctx context.Context, dialer *net.Dialer, host string) ([]netip.Addr, string, error) {
	if r, via := cachedResolver(); r != nil {
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		addrs, err := r.LookupIPv4(c, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			return addrs, via, nil
		}
	}

	type res struct {
		addrs []netip.Addr
		via   string
	}
	doh := make(chan res, 1)
	sys := make(chan res, 1)

	go func() {
		strat, _ := StrategyByName("record-sni")
		r := NewResolver(dialer, strat)
		c, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		if addrs, err := r.LookupIPv4(c, host); err == nil && len(addrs) > 0 {
			setCachedResolver(r, "DoH")
			doh <- res{addrs, "DoH"}
			return
		}
		r.Close()
		doh <- res{}
	}()

	go func() {
		var sr net.Resolver
		sr.PreferGo = true
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		ips, err := sr.LookupIP(c, "ip4", host)
		if err != nil {
			sys <- res{}
			return
		}
		var out []netip.Addr
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip.To4()); ok {
				out = append(out, a)
			}
		}
		sys <- res{out, "system resolver"}
	}()

	deadline := time.After(6 * time.Second)
	for {
		select {
		case d := <-doh:
			if len(d.addrs) > 0 {
				return d.addrs, d.via, nil
			}
			select {
			case sr := <-sys:
				if len(sr.addrs) > 0 {
					return sr.addrs, sr.via, nil
				}
			case <-deadline:
			}
			return nil, "", fmt.Errorf("could not resolve %s: DNS did not answer", host)

		case sr := <-sys:
			if len(sr.addrs) == 0 {
				continue
			}
			select {
			case d := <-doh:
				if len(d.addrs) > 0 {
					return d.addrs, d.via, nil
				}
			case <-time.After(400 * time.Millisecond):
			}
			return sr.addrs, sr.via, nil

		case <-deadline:
			return nil, "", fmt.Errorf("could not resolve %s: DNS timed out", host)
		}
	}
}

func tryStrategy(ctx context.Context, dialer *net.Dialer, strat Strategy, addr, host string, timeout time.Duration) TuneResult {
	start := time.Now()
	r := TuneResult{Strategy: strat.Name}

	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := DialTLSWithStrategy(c, dialer, addr, host, strat)
	r.Millis = time.Since(start).Milliseconds()
	if err != nil {
		r.Error = err.Error()
		return r
	}
	conn.Close()
	r.OK = true
	return r
}

func AutoTune(cfg *Config, dialer *net.Dialer) (Strategy, TuneReport) {
	hosts := cfg.AutoTuneHosts
	if len(hosts) == 0 {
		hosts = cfg.SelfTestHosts
	}
	timeout := cfg.HandshakeTimeout()
	ctx := context.Background()

	none, _ := StrategyByName("none")
	fallback, _ := StrategyByName("record-sni")
	report := TuneReport{Chosen: fallback.Name}

	var probeHost, probeAddr string
	for _, host := range hosts {
		addrs, via, err := bootstrapResolve(ctx, dialer, host)
		if err != nil || len(addrs) == 0 {
			continue
		}
		report.DNSVia = via
		addr := net.JoinHostPort(addrs[0].String(), "443")

		res := tryStrategy(ctx, dialer, none, addr, host, timeout)
		if !res.OK {
			probeHost, probeAddr = host, addr
			report.ProbeHost = host
			report.Blocked = true
			report.Results = append(report.Results, res)
			break
		}
	}

	if !report.Blocked {
		report.Note = "nothing appears blocked on this connection; using a safe default"
		return fallback, report
	}

	for _, strat := range Strategies {
		if strat.Name == "none" {
			continue
		}
		res := tryStrategy(ctx, dialer, strat, probeAddr, probeHost, timeout)
		report.Results = append(report.Results, res)
		if res.OK {
			report.Chosen = strat.Name
			return strat, report
		}
	}

	report.AllFailed = true
	report.Note = "no strategy defeated this provider's blocking; falling back to " + fallback.Name
	return fallback, report
}

func ChooseStrategy(cfg *Config, dialer *net.Dialer) (Strategy, error) {
	if cfg.Strategy != "" && cfg.Strategy != "auto" {
		strat, ok := StrategyByName(cfg.Strategy)
		if !ok {
			return Strategy{}, fmt.Errorf("unknown strategy %q; available: %v", cfg.Strategy, StrategyNames())
		}
		log.Printf("strategy %q (%s), set in config", strat.Name, strat.Short)
		return strat, nil
	}

	log.Print("measuring which bypass works on this connection...")
	strat, report := AutoTune(cfg, dialer)
	for _, r := range report.Results {
		if r.OK {
			log.Printf("  %-16s works (%dms)", r.Strategy, r.Millis)
		} else {
			log.Printf("  %-16s no (%dms)", r.Strategy, r.Millis)
		}
	}
	if report.Blocked {
		log.Printf("probe host %s is blocked here; DNS via %s", report.ProbeHost, report.DNSVia)
	}
	if report.Note != "" {
		log.Print(report.Note)
	}
	log.Printf("strategy %q (%s)", strat.Name, strat.Short)
	return strat, nil
}
