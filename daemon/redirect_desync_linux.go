//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
)

type desyncRedirector struct {
	cfg    DesyncConfig
	nfq    *nfqueue.Nfqueue
	sender *rawSender
	nft    queueRules
	cancel context.CancelFunc
}

func newDesyncRedirector(cfg DesyncConfig) *desyncRedirector {
	return &desyncRedirector{cfg: cfg}
}

const desyncQueueNum = 0x6570

var testOnlyDstIP = parseTestDstIP()

func (d *desyncRedirector) Start(appCfg *Config) error {
	sender, err := newRawSender(appCfg.FWMark)
	if err != nil {
		return err
	}
	d.sender = sender

	rules, err := installQueueRules(appCfg, desyncQueueNum, testOnlyDstIP)
	if err != nil {
		sender.Close()
		return fmt.Errorf("installing queue rules: %w", err)
	}
	d.nft = rules

	nfq, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      desyncQueueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	})
	if err != nil {
		rules.remove()
		sender.Close()
		return fmt.Errorf("opening netfilter queue (needs root): %w", err)
	}
	d.nfq = nfq

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	err = nfq.RegisterWithErrorFunc(ctx, d.onPacket, func(e error) int {
		log.Printf("nfqueue error: %v", e)
		return 0
	})
	if err != nil {
		cancel()
		nfq.Close()
		rules.remove()
		sender.Close()
		return fmt.Errorf("registering queue handler: %w", err)
	}

	storeMethodLinux("packet desync (" + string(d.cfg.Method) + ")")
	return nil
}

func (d *desyncRedirector) onPacket(a nfqueue.Attribute) int {
	if a.PacketID == nil || a.Payload == nil {
		return 0
	}
	id := *a.PacketID
	pkt := *a.Payload

	out, ok := Desync(pkt, d.cfg)
	if !ok {
		d.nfq.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	sent, failed := 0, 0
	for _, op := range out {
		var err error
		if op.TTL > 0 {
			err = d.sender.sendWithTTL(op.Data, op.TTL)
		} else {
			err = d.sender.send(op.Data)
		}
		if err != nil {
			failed++
			log.Printf("desync send error: %v", err)
		} else {
			sent++
		}
	}
	log.Printf("desync: ClientHello caught, emitted %d packets (%d failed), dropping original", sent, failed)
	d.nfq.SetVerdict(id, nfqueue.NfDrop)
	return 0
}

func (d *desyncRedirector) Status() string {
	return "packet desync active (" + string(d.cfg.Method) + "): no proxy, works on reassembling censors"
}

func (d *desyncRedirector) Stop() error {
	if d.cancel != nil {
		d.cancel()
	}
	if d.nfq != nil {
		d.nfq.Close()
	}
	if d.nft != nil {
		d.nft.remove()
	}
	if d.sender != nil {
		d.sender.Close()
	}
	storeMethodLinux("")
	return nil
}

func parseTestDstIP() []byte {
	v := envLookup("EzPi_TEST_DST_IP")
	if v == "" {
		return nil
	}
	ip := netParseIP4(v)
	return ip
}

func envLookup(k string) string { return os.Getenv(k) }
func netParseIP4(v string) []byte {
	ip := net.ParseIP(v)
	if ip == nil {
		return nil
	}
	return ip.To4()
}
