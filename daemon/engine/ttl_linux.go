//go:build linux

package engine

import (
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

func applyTTL(w io.Writer, ttl int) func() {
	sc, ok := w.(syscall.Conn)
	if !ok {
		return func() {}
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return func() {}
	}
	set := func(v int) {
		rc.Control(func(fd uintptr) {
			unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, v)
			unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, v)
		})
	}
	set(ttl)
	return func() { set(64) }
}
