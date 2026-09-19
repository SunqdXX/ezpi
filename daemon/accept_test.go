package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type flakyListener struct {
	net.Listener
	fails atomic.Int32
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.fails.Add(1) <= 3 {
		return nil, errors.New("accept4: too many open files")
	}
	return f.Listener.Accept()
}

func TestAcceptLoopSurvivesTemporaryErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		serveListener(&flakyListener{Listener: ln}, func(c net.Conn) { c.Close(); got <- struct{}{} })
		close(done)
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("a temporary accept error stopped the proxy for good")
	}
	ln.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("closing the listener did not stop the loop")
	}
}

func TestLearnBlockIPsNeedsTheSameFakeAnswerForTwoNames(t *testing.T) {
	block := netip.MustParseAddr("195.175.254.2")
	sys := map[string][]string{
		"discord.com":    {"195.175.254.2"},
		"www.roblox.com": {"195.175.254.2"},
		"discordapp.com": {"162.159.1.1"},
	}
	real := map[string][]string{
		"discord.com":    {"162.159.135.232"},
		"www.roblox.com": {"128.116.1.1"},
		"discordapp.com": {"162.159.2.2"},
	}
	got := learnBlockIPs(stub(sys), stub(real), []string{"discord.com", "www.roblox.com", "discordapp.com"})
	if len(got) != 1 || got[0] != block {
		t.Fatalf("learned %v, want only %v", got, block)
	}
}

func stub(m map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range m[host] {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func TestADeadNetworkNeverSwitchesToThePacketEngine(t *testing.T) {
	if wantsPacketEngine(TuneReport{AllFailed: true, NetworkDown: true}, true) {
		t.Fatal("every strategy failed only because the network was down; that must not switch engines")
	}
	if wantsPacketEngine(TuneReport{AllFailed: false}, true) {
		t.Fatal("switched engines although a strategy worked")
	}
}
