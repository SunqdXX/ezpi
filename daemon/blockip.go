package main

import (
	"context"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

var knownBlockPages = []string{"195.175.254.2"}

var blockProbeHosts = []string{"discord.com", "www.roblox.com", "discordapp.com"}

type blockSet struct {
	mu sync.RWMutex
	m  map[netip.Addr]bool
}

func newBlockSet() *blockSet {
	b := &blockSet{m: map[netip.Addr]bool{}}
	for _, s := range knownBlockPages {
		b.m[netip.MustParseAddr(s)] = true
	}
	return b
}

func (b *blockSet) has(ip netip.Addr) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.m[ip.Unmap()]
}

func (b *blockSet) add(ip netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	ip = ip.Unmap()
	if b.m[ip] {
		return false
	}
	b.m[ip] = true
	return true
}

type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func learnBlockIPs(system, real lookupFunc, hosts []string) []netip.Addr {
	seen := map[netip.Addr]int{}
	for _, h := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		sys, err1 := system(ctx, h)
		truth, err2 := real(ctx, h)
		cancel()
		if err1 != nil || err2 != nil || len(truth) == 0 {
			continue
		}
		ok := map[netip.Addr]bool{}
		for _, a := range truth {
			ok[a.Unmap()] = true
		}
		fake := map[netip.Addr]bool{}
		for _, a := range sys {
			if a = a.Unmap(); !ok[a] {
				fake[a] = true
			}
		}
		for a := range fake {
			seen[a]++
		}
	}
	var out []netip.Addr
	for a, n := range seen {
		if n >= 2 {
			out = append(out, a)
		}
	}
	return out
}

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
}

func keepLearningBlockPages(b *blockSet, r *Resolver, stop <-chan struct{}) {
	for {
		for _, ip := range learnBlockIPs(systemLookup, r.LookupIPv4, blockProbeHosts) {
			if b.add(ip) {
				log.Printf("ISP block page address learned: %s", ip)
			}
		}
		select {
		case <-stop:
			return
		case <-time.After(10 * time.Minute):
		}
	}
}
