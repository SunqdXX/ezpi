package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	serviceUnit = "ezpi.service"
	pidPath     = "/run/ezpi.pid"
	statePath   = "/run/ezpi.state"
	logPath     = "/run/ezpi.log"
)

func hasSystemdUnit() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	out, err := exec.Command("systemctl", "list-unit-files", serviceUnit).Output()
	return err == nil && strings.Contains(string(out), serviceUnit)
}

func running() (bool, string) {
	if hasSystemdUnit() {
		out, _ := exec.Command("systemctl", "is-active", serviceUnit).Output()
		if strings.TrimSpace(string(out)) == "active" {
			return true, "systemd"
		}
		return false, "systemd"
	}
	if pid := readPID(); pid > 0 && processAlive(pid) {
		return true, "direct"
	}
	return false, "direct"
}

func enable() error {
	if on, _ := running(); on {
		fmt.Println("EzPi is already on.")
		return nil
	}
	if hasSystemdUnit() {
		if err := systemctlVerb("start"); err != nil {
			return fmt.Errorf("could not start EzPi: %w", err)
		}
	} else {
		if err := startDirect(); err != nil {
			return err
		}
	}
	fmt.Println("EzPi started successfully.")
	return nil
}

func disable() error {
	on, how := running()
	if !on {
		fmt.Println("EzPi is already off.")
		return nil
	}
	if how == "systemd" {
		if err := systemctlVerb("stop"); err != nil {
			return fmt.Errorf("could not stop EzPi: %w", err)
		}
	} else {
		if err := stopDirect(); err != nil {
			return err
		}
	}
	fmt.Println("EzPi stopped.")
	return nil
}

func status() {
	on, how := running()
	if !on {
		fmt.Println("EzPi: OFF")
		return
	}
	fmt.Printf("EzPi: ON  (%s)\n", how)
	for _, line := range readState() {
		fmt.Println("  " + line)
	}
}

func systemctlVerb(verb string) error {
	if out, err := exec.Command("systemctl", verb, serviceUnit).CombinedOutput(); err == nil {
		return nil
	} else if len(out) > 0 && !strings.Contains(string(out), "Interactive authentication required") {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return exec.Command("sudo", "systemctl", verb, serviceUnit).Run()
}

func startDirect() error {
	if os.Geteuid() != 0 {
		self, _ := os.Executable()
		c := exec.Command("sudo", self, "--enable")
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run()
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	logf, _ := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)

	cmd := exec.Command(self, "-daemon", "-config", DefaultConfigPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	if logf != nil {
		cmd.Stdout, cmd.Stderr = logf, logf
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start the engine: %w", err)
	}
	writePID(cmd.Process.Pid)
	go cmd.Wait()
	return nil
}

func stopDirect() error {
	if os.Geteuid() != 0 {
		self, _ := os.Executable()
		c := exec.Command("sudo", self, "--disable")
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run()
	}
	pid := readPID()
	if pid <= 0 {
		return fmt.Errorf("no running engine found")
	}
	syscall.Kill(pid, syscall.SIGTERM)
	os.Remove(pidPath)
	return nil
}

func readPID() int {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func writePID(pid int) {
	os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0o644)
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func writeState(lines []string) {
	os.WriteFile(statePath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func clearState() { os.Remove(statePath) }

func readState() []string {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
