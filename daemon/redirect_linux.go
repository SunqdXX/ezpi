//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
)

type linuxFirewall interface {
	Remove() error
	Status() string
}

type linuxRedirector struct {
	fw linuxFirewall
}

func NewRedirector() Redirector { return &linuxRedirector{} }

func (l *linuxRedirector) Start(cfg *Config) error {
	n, nftErr := Install(cfg)
	if nftErr == nil {
		l.fw = n
		return nil
	}
	log.Printf("nftables unavailable (%v); trying iptables", nftErr)

	if !iptablesAvailable() {
		return fmt.Errorf("neither nftables nor iptables could be used: %w", nftErr)
	}
	ipt, iptErr := installIptables(cfg)
	if iptErr != nil {
		return fmt.Errorf("nftables failed (%v) and iptables failed: %w", nftErr, iptErr)
	}
	l.fw = ipt
	return nil
}

func (l *linuxRedirector) Destination(c net.Conn) (string, error) {
	tcp, ok := c.(*net.TCPConn)
	if !ok {
		return "", errNotTCP
	}
	dst, err := OriginalDst(tcp)
	if err != nil {
		return "", err
	}
	return dst.String(), nil
}

func (l *linuxRedirector) Dialer(cfg *Config) *net.Dialer {
	return markedDialer(cfg.FWMark, cfg.DialTimeoutSec)
}

func (l *linuxRedirector) Status() string {
	if l.fw == nil {
		return "no firewall rules installed"
	}
	return l.fw.Status()
}

func (l *linuxRedirector) Stop() error {
	if l.fw == nil {
		return nil
	}
	err := l.fw.Remove()
	l.fw = nil
	return err
}
