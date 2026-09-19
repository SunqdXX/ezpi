//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const iptChain = "EZPI"
const iptQuicChain = "EZPI_QUIC"

type iptablesFirewall struct {
	cmds []string
}

func iptablesAvailable() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

func runIpt(bin string, args ...string) error {
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", bin, strings.Join(args, " "),
			strings.TrimSpace(string(out)))
	}
	return nil
}

func installIptables(cfg *Config) (*iptablesFirewall, error) {
	fw := &iptablesFirewall{}

	type variant struct {
		bin  string
		skip []string
	}
	variants := []variant{{"iptables", neverRedirect4}}
	if _, err := exec.LookPath("ip6tables"); err == nil {
		variants = append(variants, variant{"ip6tables", neverRedirect6})
	}

	port := strconv.Itoa(int(cfg.ListenPort))
	target := strconv.Itoa(int(cfg.TargetPort))
	mark := "0x" + strconv.FormatUint(uint64(cfg.FWMark), 16)

	var firstErr error
	for _, v := range variants {
		removeIptablesFor(v.bin)

		if err := runIpt(v.bin, "-t", "nat", "-N", iptChain); err != nil {
			if v.bin == "iptables" {
				firstErr = err
			}
			continue
		}

		steps := [][]string{
			{"-t", "nat", "-A", iptChain, "-m", "mark", "--mark", mark, "-j", "RETURN"},
		}
		for _, iface := range cfg.SkipInterfaces {
			steps = append(steps, []string{"-t", "nat", "-A", iptChain, "-o", iface, "-j", "RETURN"})
		}
		for _, cidr := range v.skip {
			steps = append(steps, []string{"-t", "nat", "-A", iptChain, "-d", cidr, "-j", "RETURN"})
		}
		steps = append(steps,
			[]string{"-t", "nat", "-A", iptChain, "-p", "tcp", "--dport", target,
				"-j", "REDIRECT", "--to-ports", port},
			[]string{"-t", "nat", "-A", "OUTPUT", "-j", iptChain},
		)

		steps = append(steps, []string{"-t", "filter", "-N", iptQuicChain})
		steps = append(steps, []string{"-t", "filter", "-A", iptQuicChain, "-m", "mark", "--mark", mark, "-j", "RETURN"})
		for _, iface := range cfg.SkipInterfaces {
			steps = append(steps, []string{"-t", "filter", "-A", iptQuicChain, "-o", iface, "-j", "RETURN"})
		}
		for _, cidr := range v.skip {
			steps = append(steps, []string{"-t", "filter", "-A", iptQuicChain, "-d", cidr, "-j", "RETURN"})
		}
		rejectWith := "icmp-port-unreachable"
		if v.bin == "ip6tables" {
			rejectWith = "icmp6-port-unreachable"
		}
		steps = append(steps,
			[]string{"-t", "filter", "-A", iptQuicChain, "-p", "udp", "--dport", target, "-j", "REJECT", "--reject-with", rejectWith},
			[]string{"-t", "filter", "-A", "OUTPUT", "-j", iptQuicChain},
		)

		ok := true
		for _, st := range steps {
			if err := runIpt(v.bin, st...); err != nil {
				if v.bin == "iptables" && firstErr == nil {
					firstErr = err
				}
				ok = false
				break
			}
		}
		if ok {
			fw.cmds = append(fw.cmds, v.bin)
		} else {
			removeIptablesFor(v.bin)
		}
	}

	if len(fw.cmds) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("iptables produced no usable rules")
		}
		return nil, firstErr
	}
	return fw, nil
}

func removeIptablesFor(bin string) {
	exec.Command(bin, "-t", "nat", "-D", "OUTPUT", "-j", iptChain).Run()
	exec.Command(bin, "-t", "nat", "-F", iptChain).Run()
	exec.Command(bin, "-t", "nat", "-X", iptChain).Run()
	exec.Command(bin, "-t", "filter", "-D", "OUTPUT", "-j", iptQuicChain).Run()
	exec.Command(bin, "-t", "filter", "-F", iptQuicChain).Run()
	exec.Command(bin, "-t", "filter", "-X", iptQuicChain).Run()
}

func (f *iptablesFirewall) Remove() error {
	for _, bin := range f.cmds {
		removeIptablesFor(bin)
	}
	f.cmds = nil
	return nil
}

func (f *iptablesFirewall) Status() string {
	families := "IPv4"
	if len(f.cmds) > 1 {
		families = "IPv4+IPv6"
	}
	return "iptables rules installed (" + families + "); removed when EzPi stops"
}
