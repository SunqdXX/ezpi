//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
)

type iptQueueRules struct {
	args [][]string
}

func installQueueIptables(cfg *Config, queueNum uint16, onlyDstIP []byte) (*iptQueueRules, error) {
	ipt, err := exec.LookPath("iptables")
	if err != nil {
		return nil, fmt.Errorf("iptables not found: %w", err)
	}

	mark := strconv.Itoa(int(cfg.FWMark))
	rule := []string{"-t", "mangle", "OUTPUT",
		"-p", "tcp", "--dport", strconv.Itoa(int(cfg.TargetPort)),
		"-m", "connbytes", "--connbytes", "0:" + strconv.Itoa(queueEarlyPackets-1),
		"--connbytes-dir", "original", "--connbytes-mode", "packets",
		"-m", "mark", "!", "--mark", mark,
		"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNum)), "--queue-bypass"}
	if len(onlyDstIP) == 4 {
		dst := fmt.Sprintf("%d.%d.%d.%d", onlyDstIP[0], onlyDstIP[1], onlyDstIP[2], onlyDstIP[3])
		rule = append([]string{"-t", "mangle", "OUTPUT", "-d", dst,
			"-p", "tcp", "--dport", strconv.Itoa(int(cfg.TargetPort)),
			"-m", "connbytes", "--connbytes", "0:" + strconv.Itoa(queueEarlyPackets-1),
			"--connbytes-dir", "original", "--connbytes-mode", "packets",
			"-m", "mark", "!", "--mark", mark,
			"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNum)), "--queue-bypass"}, nil...)
	}

	full := append([]string{"-t", "mangle", "-A", "OUTPUT"}, rule[3:]...)
	if out, err := exec.Command(ipt, full...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("iptables add: %s", string(out))
	}
	del := append([]string{"-t", "mangle", "-D", "OUTPUT"}, rule[3:]...)
	return &iptQueueRules{args: [][]string{del}}, nil
}

func (r *iptQueueRules) remove() {
	ipt, err := exec.LookPath("iptables")
	if err != nil {
		return
	}
	for _, a := range r.args {
		exec.Command(ipt, a...).Run()
	}
}
