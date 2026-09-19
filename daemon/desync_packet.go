package main

import (
	"crypto/rand"
	"encoding/binary"
)

func isClientHello(payload []byte) bool {
	if len(payload) < recHeaderLen+1 {
		return false
	}
	if payload[0] != recHandshake || payload[recHeaderLen] != hsClientHello {
		return false
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	return recLen >= 4 && recLen <= maxRecord
}

func handshakeBytes(payload []byte) ([]byte, bool) {
	if !isClientHello(payload) {
		return nil, false
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	end := recHeaderLen + recLen
	if end > len(payload) {
		end = len(payload)
	}
	return payload[recHeaderLen:end], true
}

func isQUICInitial(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	if payload[0]&0x80 == 0 {
		return false
	}
	version := binary.BigEndian.Uint32(payload[1:5])
	return version != 0
}

func buildClientHello(sni string) []byte {
	host := []byte(sni)
	server := append([]byte{0x00}, byte(len(host)>>8), byte(len(host)))
	server = append(server, host...)
	list := append([]byte{byte(len(server) >> 8), byte(len(server))}, server...)
	sniExt := append([]byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}, list...)

	rnd := make([]byte, 32)
	rand.Read(rnd)

	body := append([]byte{0x03, 0x03}, rnd...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(sniExt)>>8), byte(len(sniExt)))
	body = append(body, sniExt...)

	hs := append([]byte{hsClientHello,
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	rec := append([]byte{recHandshake, 0x03, 0x01,
		byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

func setIPTotalLen(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(pkt []byte, ihl int) uint16 {
	tcp := pkt[ihl:]
	var sum uint32
	for _, b := range [][]byte{pkt[12:16], pkt[16:20]} {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
	}
	sum += uint32(pkt[9])
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func fixChecksums(pkt []byte, ihl int) {
	if len(pkt) < ihl+20 {
		return
	}
	pkt[10], pkt[11] = 0, 0
	c := ipChecksum(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], c)

	pkt[ihl+16], pkt[ihl+17] = 0, 0
	t := tcpChecksum(pkt, ihl)
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], t)
}

func corruptTCPChecksum(pkt []byte, ihl int) {
	if len(pkt) < ihl+18 {
		return
	}
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], 0x1)
}

func setTCPSeq(pkt []byte, ihl int, seq uint32) {
	if len(pkt) < ihl+8 {
		return
	}
	binary.BigEndian.PutUint32(pkt[ihl+4:ihl+8], seq)
}

func clearACKFlag(pkt []byte, ihl int) {
	if len(pkt) < ihl+14 {
		return
	}
	pkt[ihl+13] &^= 0x10
}
