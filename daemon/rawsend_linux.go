//go:build linux

package main

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

type rawSender struct {
	mu sync.Mutex
	fd int
}

func newRawSender(mark uint32) (*rawSender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("opening raw socket (needs root): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("SO_MARK: %w", err)
		}
	}
	return &rawSender{fd: fd}, nil
}

func (s *rawSender) send(pkt []byte) error {
	if len(pkt) < 20 {
		return fmt.Errorf("packet too short")
	}
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	sa := &unix.SockaddrInet4{Addr: dst}

	s.mu.Lock()
	defer s.mu.Unlock()
	return unix.Sendto(s.fd, pkt, 0, sa)
}

func (s *rawSender) sendWithTTL(pkt []byte, ttl uint8) error {
	if len(pkt) < 20 {
		return fmt.Errorf("packet too short")
	}
	orig := pkt[8]
	pkt[8] = ttl
	pkt[10], pkt[11] = 0, 0
	c := ipChecksum(pkt[:ipHeaderLen(pkt)])
	pkt[10] = byte(c >> 8)
	pkt[11] = byte(c)
	err := s.send(pkt)
	pkt[8] = orig
	return err
}

func (s *rawSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd >= 0 {
		err := unix.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

func ipHeaderLen(pkt []byte) int {
	if len(pkt) < 1 {
		return 20
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return 20
	}
	return ihl
}
