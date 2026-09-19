package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const maxConnectHeader = 8 << 10

func readCONNECT(c net.Conn, timeout time.Duration) (string, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	defer c.SetReadDeadline(time.Time{})

	var head []byte
	buf := make([]byte, 1)
	for len(head) < maxConnectHeader {
		n, err := c.Read(buf)
		if err != nil {
			return "", fmt.Errorf("reading CONNECT: %w", err)
		}
		if n == 0 {
			continue
		}
		head = append(head, buf[0])
		if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
			break
		}
	}
	if len(head) >= maxConnectHeader {
		return "", errors.New("CONNECT header too large")
	}

	line, _, _ := strings.Cut(string(head), "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "CONNECT") {
		writeStatus(c, "405 Method Not Allowed")
		return "", fmt.Errorf("expected CONNECT, got %q", line)
	}

	target := parts[1]
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	if err := writeStatus(c, "200 Connection Established"); err != nil {
		return "", err
	}
	return target, nil
}

func writeStatus(c net.Conn, status string) error {
	_, err := io.WriteString(c, "HTTP/1.1 "+status+"\r\n\r\n")
	return err
}

func sendCONNECT(c net.Conn, target string, timeout time.Duration) error {
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return err
	}

	var head []byte
	buf := make([]byte, 1)
	for len(head) < maxConnectHeader {
		n, err := c.Read(buf)
		if err != nil {
			return fmt.Errorf("proxy did not answer CONNECT: %w", err)
		}
		if n == 0 {
			continue
		}
		head = append(head, buf[0])
		if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
			break
		}
	}
	if len(head) >= maxConnectHeader {
		return errors.New("proxy sent an oversized reply to CONNECT")
	}

	status, _, _ := strings.Cut(string(head), "\r\n")
	fields := strings.Fields(status)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return fmt.Errorf("proxy sent a malformed reply: %q", status)
	}
	if fields[1] != "200" {
		return fmt.Errorf("proxy refused CONNECT: %s", strings.TrimSpace(status))
	}

	c.SetDeadline(time.Time{})
	return nil
}
