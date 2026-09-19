package ezpitun

import (
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"ezpi/engine"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Protector interface {
	Protect(fd int) bool
}

const nicID = 1

type tunnel struct {
	stack     *stack.Stack
	protector Protector
	dialer    *net.Dialer
	strats    []engine.Strategy
	opts      engine.RelayOpts
}

var (
	mu      sync.Mutex
	running *tunnel
)

func Start(fd int, mtu int, p Protector) error {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		return errors.New("ezpitun already running")
	}
	if mtu <= 0 {
		mtu = 1500
	}
	link, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            uint32(mtu),
		EthernetHeader: false,
	})
	if err != nil {
		return err
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if e := s.CreateNIC(nicID, link); e != nil {
		return errors.New(e.String())
	}
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	t := &tunnel{
		stack:     s,
		protector: p,
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
		strats:    buildStrategies(),
		opts:      engine.RelayOpts{Handshake: 5 * time.Second, Probe: 3 * time.Second, Idle: 3 * time.Minute},
	}
	t.dialer.Control = t.control

	if rs, ok := engine.StrategyByName("record-sni"); ok {
		engine.SetResolver(engine.NewResolver(t.dialer, rs))
	}

	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, e := r.CreateEndpoint(&wq)
		if e != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		go t.handleTCP(conn, dst)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort == 443 {
			return false
		}
		var wq waiter.Queue
		ep, e := r.CreateEndpoint(&wq)
		if e != nil {
			return true
		}
		conn := gonet.NewUDPConn(&wq, ep)
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		go t.handleUDP(conn, dst)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	running = t
	log.Printf("ezpitun: up (fd=%d mtu=%d, %d strategies)", fd, mtu, len(t.strats))
	return nil
}

func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if running != nil {
		running.stack.Close()
		running = nil
		log.Print("ezpitun: stopped")
	}
}

func buildStrategies() []engine.Strategy {
	names := []string{"record-sni", "tcp-sni", "record-sni+tcp", "record-multi", "tcp-tiny", "disorder"}
	seen := map[string]bool{}
	var out []engine.Strategy
	for _, n := range names {
		if seen[n] {
			continue
		}
		if s, ok := engine.StrategyByName(n); ok {
			out = append(out, s)
			seen[n] = true
		}
	}
	if len(out) == 0 {
		out = engine.Strategies
	}
	return out
}

func (t *tunnel) control(network, address string, c syscall.RawConn) error {
	var perr error
	if e := c.Control(func(fd uintptr) {
		if t.protector != nil && !t.protector.Protect(int(fd)) {
			perr = errors.New("protect failed")
		}
	}); e != nil {
		return e
	}
	return perr
}

func (t *tunnel) handleTCP(client net.Conn, dst string) {
	defer client.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered in handleTCP %s: %v", dst, r)
		}
	}()
	dial := func(addr string) (net.Conn, error) { return t.dialer.Dial("tcp", addr) }
	if err := engine.Relay(client, dst, dial, t.strats, t.opts); err != nil {
		log.Printf("relay %s: %v", dst, err)
	}
}

func (t *tunnel) handleUDP(client net.Conn, dst string) {
	defer client.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered in handleUDP %s: %v", dst, r)
		}
	}()
	up, err := t.dialer.Dial("udp", dst)
	if err != nil {
		return
	}
	defer up.Close()
	relayPlain(client, up)
}

func relayPlain(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.SetReadDeadline(time.Now())
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
