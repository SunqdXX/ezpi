package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "3.31"

var errNotTCP = errors.New("connection is not TCP")

func dialSeconds(n int) time.Duration { return time.Duration(n) * time.Second }

func main() {
	if runtime.NumCPU() > 4 {
		runtime.GOMAXPROCS(4)
	}

	var (
		configPath = flag.String("config", DefaultConfigPath, "path to config file")
		selftest   = flag.Bool("selftest", false, "probe known-blocked hosts and report; needs no privileges")
		asJSON     = flag.Bool("json", false, "machine-readable output for -selftest")
		version    = flag.Bool("version", false, "print version and exit")
		restore    = flag.Bool("restore", false, "undo any leftover system changes and exit")
		tune       = flag.Bool("tune", false, "measure which bypass works on this connection and exit")
		daemonMode = flag.Bool("daemon", false, "run the bypass engine (the service uses this)")
		remove     = flag.Bool("uninstall", false, "show how to remove EzPi")
		doEnable   = flag.Bool("enable", false, "turn the bypass on")
		doDisable  = flag.Bool("disable", false, "turn the bypass off")
		doStatus   = flag.Bool("status", false, "show whether the bypass is on and what it is doing")
		doCheck    = flag.Bool("check", false, "run a live test and report if the bypass actually works")
		doWizard   = flag.Bool("wizard", false, "show the logo and a short explanation of what EzPi is")
	)
	flag.Parse()

	switch {
	case *doWizard:
		wizard()
		return
	case *doEnable:
		exitOn(enable())
		return
	case *doDisable:
		exitOn(disable())
		return
	case *doStatus:
		status()
		return
	}
	if *doCheck {
		*selftest = true
	}

	if *version {
		fmt.Printf("EzPi %s (%s)\n", Version, platformName)
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *restore {
		if err := restoreSystem(cfg); err != nil {
			log.Fatalf("restore: %v", err)
		}
		fmt.Println("system network settings restored")
		return
	}

	if *remove {
		fmt.Println("To remove EzPi, run:  sudo ./install.sh --uninstall")
		return
	}

	if *tune {
		strat, report := AutoTune(cfg, &net.Dialer{Timeout: cfg.DialTimeout()})
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(report)
			return
		}
		if report.Blocked {
			fmt.Printf("probe host %s is blocked here (DNS via %s)\n\n", report.ProbeHost, report.DNSVia)
		}
		for _, r := range report.Results {
			mark := "no "
			if r.OK {
				mark = "YES"
			}
			fmt.Printf("  %s  %-18s %5dms  %s\n", mark, r.Strategy, r.Millis, r.Error)
		}
		if report.Note != "" {
			fmt.Printf("\n%s\n", report.Note)
		}
		fmt.Printf("\nchosen: %s (%s)\n", strat.Name, strat.Short)
		if lat := strat.AddedLatency(); lat > 0 {
			fmt.Printf("this adds %v to each new connection\n", lat)
		}
		return
	}

	if *selftest {
		st := RunSelfTest(cfg)
		writeSelfTest(os.Stdout, st, *asJSON)
		if !st.OK || !st.Conclusive {
			os.Exit(1)
		}
		return
	}

	if !*daemonMode {
		if on, _ := running(); on {
			exitOn(disable())
		} else {
			exitOn(enable())
		}
		return
	}

	if err := runDaemon(cfg); err != nil {
		log.Fatalf("ezpi: %v", err)
	}
}

func runDaemon(cfg *Config) error {
	if err := requirePrivilege(); err != nil {
		return err
	}

	if cfg.Engine == "desync" || preferDesyncEngine(cfg) {
		if err := runDesync(cfg); err != nil {
			log.Printf("packet engine could not start (%v); using the fallback", err)
		} else {
			return nil
		}
	}

	listeners, err := listenLoopback(cfg.ListenPort)
	if err != nil {
		return err
	}
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	log.Printf("proxy listening on port %d (%s)", cfg.ListenPort, listenerNames(listeners))

	red := NewRedirector()
	if err := red.Start(cfg); err != nil {
		return fmt.Errorf("installing redirect: %w", err)
	}
	defer func() {
		if err := red.Stop(); err != nil {
			log.Printf("removing redirect: %v", err)
		} else {
			log.Print("redirect removed")
		}
	}()

	log.Print(red.Status())
	log.Printf("redirecting tcp/%d, skipping interfaces %v", cfg.TargetPort, cfg.SkipInterfaces)
	writeState([]string{
		"engine:  " + engineName(cfg),
		"method:  " + activeMethod(),
	})
	defer clearState()

	autoMode := cfg.Engine == "auto" || cfg.Engine == ""
	escalate := false

	held := newStrategyHolder(cfg)
	go func() {
		strat, report := AutoTune(cfg, red.Dialer(cfg))
		for _, r := range report.Results {
			if r.OK {
				log.Printf("  %-16s works (%dms)", r.Strategy, r.Millis)
			}
		}
		if report.AllFailed && autoMode && desyncSupported() {
			log.Print("no proxy technique got through; switching to the packet engine")
			escalate = true
			for _, l := range listeners {
				l.Close()
			}
			return
		}
		if lat := strat.AddedLatency(); lat > 0 {
			log.Printf("note: this strategy adds %v to each new connection", lat)
		}
		strats := fallbackOrder(strat, cfg.Retries)
		held.set(strats)
		writeState([]string{
			"engine:   proxy",
			"strategy: " + strat.Name,
			"covering: tcp/" + itoa(int(cfg.TargetPort)) + ", IPv4+IPv6",
			"quic:     udp/" + itoa(int(cfg.TargetPort)) + " rejected (instant TCP fallback)",
			"dns:      DoH (defeats ISP DNS poisoning)",
		})
		if len(strats) > 1 {
			log.Printf("if a connection fails it retries with: %s", strategyList(strats[1:]))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-stop
		log.Printf("caught %v, shutting down", s)
		for _, l := range listeners {
			l.Close()
		}
	}()

	dialer := red.Dialer(cfg)
	if rs, ok := StrategyByName("record-sni"); ok {
		proxyResolver = NewResolver(dialer, rs)
	}

	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			self := l.Addr().String()
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go handle(c, cfg, red, dialer, self, held.get())
			}
		}(l)
	}
	wg.Wait()

	if escalate {
		red.Stop()
		return runDesync(cfg)
	}
	return nil
}

type strategyHolder struct {
	mu     sync.RWMutex
	strats []Strategy
}

func newStrategyHolder(cfg *Config) *strategyHolder {
	def, ok := StrategyByName("record-sni")
	if !ok {
		def = Strategies[0]
	}
	if cfg.Strategy != "" && cfg.Strategy != "auto" {
		if s, ok := StrategyByName(cfg.Strategy); ok {
			def = s
		}
	}
	return &strategyHolder{strats: fallbackOrder(def, cfg.Retries)}
}

func (h *strategyHolder) get() []Strategy {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.strats
}

func (h *strategyHolder) set(s []Strategy) {
	h.mu.Lock()
	h.strats = s
	h.mu.Unlock()
}

func fallbackOrder(chosen Strategy, retries int) []Strategy {
	preferred := []string{
		chosen.Name,
		"record-sni",
		"tcp-sni",
		"record-sni+tcp",
		"record-multi",
		"tcp-tiny",
	}
	seen := map[string]bool{}
	out := make([]Strategy, 0, len(preferred))
	for _, name := range preferred {
		if name == "" || name == "none" || seen[name] {
			continue
		}
		if s, ok := StrategyByName(name); ok {
			out = append(out, s)
			seen[name] = true
		}
	}
	return out
}

func strategyList(ss []Strategy) string {
	names := make([]string, 0, len(ss))
	for _, s := range ss {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

func listenLoopback(port uint16) ([]net.Listener, error) {
	var out []net.Listener
	var firstErr error
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		addr := fmt.Sprintf("%s:%d", host, port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Printf("not listening on %s: %v", addr, err)
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("could not listen on port %d: %w", port, firstErr)
	}
	return out, nil
}

func listenerNames(ls []net.Listener) string {
	names := make([]string, 0, len(ls))
	for _, l := range ls {
		names = append(names, l.Addr().String())
	}
	return strings.Join(names, ", ")
}

func handle(c net.Conn, cfg *Config, red Redirector, dialer *net.Dialer, self string, strats []Strategy) {
	defer c.Close()

	dst, err := red.Destination(c)
	if err != nil {
		log.Printf("no destination for %s: %v", c.RemoteAddr(), err)
		return
	}
	if dst == self {
		log.Printf("refusing to proxy to self from %s", c.RemoteAddr())
		return
	}

	dial := func(addr string) (net.Conn, error) { return dialer.Dial("tcp", addr) }
	opts := RelayOpts{
		Handshake: cfg.HandshakeTimeout(),
		Probe:     cfg.ProbeTimeout(),
		Idle:      cfg.IdleTimeout(),
	}
	if err := Relay(c, dst, dial, strats, opts); err != nil {
		log.Printf("relay %s: %v", dst, err)
	}
}

func useDesyncEngine(cfg *Config) bool {
	switch cfg.Engine {
	case "proxy":
		return false
	case "desync", "auto", "":
		return desyncSupported()
	}
	return false
}

func runDesync(cfg *Config) error {
	stopper, err := startDesync(cfg)
	if err != nil {
		return err
	}
	defer stopper.Stop()
	log.Print(stopper.Status())
	writeState([]string{
		"engine:   packet desync",
		"method:   " + activeMethod(),
		"covering: tcp/" + itoa(int(cfg.TargetPort)) + ", IPv4+IPv6",
	})
	defer clearState()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Print("shutting down")
	return nil
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func engineName(cfg *Config) string {
	if cfg.Engine == "desync" || preferDesyncEngine(cfg) {
		return "packet desync"
	}
	return "proxy (auto)"
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
