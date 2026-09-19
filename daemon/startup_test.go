package main

import (
	"testing"
	"time"
)

func TestStrategyIsUsableBeforeTuningFinishes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = "auto"

	held := newStrategyHolder(cfg)
	got := held.get()
	if len(got) == 0 {
		t.Fatal("no strategy available at startup; early connections would fail")
	}
	if got[0].Name != "record-sni" {
		t.Errorf("startup default is %q; expected the free, widely-effective one", got[0].Name)
	}
	if lat := got[0].AddedLatency(); lat > 0 {
		t.Errorf("startup default adds %v per connection", lat)
	}
	if len(got) < 2 {
		t.Error("no fallbacks available before tuning finishes")
	}
}

func TestExplicitStrategyAppliesAtStartup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Strategy = "tcp-tiny"
	if got := newStrategyHolder(cfg).get(); got[0].Name != "tcp-tiny" {
		t.Fatalf("startup used %q, want the configured tcp-tiny", got[0].Name)
	}
}

func TestStrategyHolderIsSafeUnderConcurrency(t *testing.T) {
	held := newStrategyHolder(DefaultConfig())
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			if len(held.get()) == 0 {
				t.Error("holder returned nothing mid-swap")
				return
			}
		}
	}()
	for i := 0; i < 500; i++ {
		held.set(fallbackOrder(Strategies[i%len(Strategies)], 2))
	}
	<-done
}

func TestEngineFailuresAreNotReportedAsBlocks(t *testing.T) {
	local := []string{
		"EzPi does not seem to be running: dial tcp 127.0.0.1:8443: connect: connection refused",
		"proxy did not answer CONNECT: EOF",
		"proxy did not answer CONNECT: read tcp 127.0.0.1:1->127.0.0.1:8443: connection reset by peer",
		"proxy refused CONNECT: 405 Method Not Allowed",
		"EOF",
		"dial tcp 127.0.0.1:8443: connectex: No connection could be made because " +
			"the target machine actively refused it.",
	}
	for _, msg := range local {
		if !looksLikeEngineDown(errUnwrap(msg)) {
			t.Errorf("would be blamed on the provider: %q", msg)
		}
	}

	censorship := []string{
		"context deadline exceeded",
		"read tcp 192.168.1.5:52176->128.116.5.3:443: wsarecv: An existing " +
			"connection was forcibly closed by the remote host.",
		"tls: first record does not look like a TLS handshake",
	}
	for _, msg := range censorship {
		if looksLikeEngineDown(errUnwrap(msg)) {
			t.Errorf("real block misreported as an engine fault: %q", msg)
		}
	}
}

type stringErr string

func (e stringErr) Error() string { return string(e) }
func errUnwrap(s string) error    { return stringErr(s) }
