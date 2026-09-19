//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ip6OriginalDst = 80

func OriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}

	if isIPv6(c) {
		return original6(raw)
	}

	var sa unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(sa))
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
			uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if errno != 0 {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", errno)
	}
	if sa.Family != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST returned family %d, want AF_INET", sa.Family)
	}

	port := sa.Port<<8 | sa.Port>>8
	return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port), nil
}

func isIPv6(c *net.TCPConn) bool {
	addr, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok || addr.IP == nil {
		return false
	}
	return addr.IP.To4() == nil
}

func original6(raw syscall.RawConn) (netip.AddrPort, error) {
	var sa unix.RawSockaddrInet6
	size := uint32(unsafe.Sizeof(sa))
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
			uintptr(unix.SOL_IPV6), uintptr(ip6OriginalDst),
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if errno != 0 {
		return netip.AddrPort{}, fmt.Errorf("IP6T_SO_ORIGINAL_DST: %w", errno)
	}
	port := sa.Port<<8 | sa.Port>>8
	return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), port), nil
}

func markedDialer(mark uint32, timeoutSec int) *net.Dialer {
	return &net.Dialer{
		Timeout: dialSeconds(timeoutSec),
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}); err != nil {
				return err
			}
			return opErr
		},
	}
}
