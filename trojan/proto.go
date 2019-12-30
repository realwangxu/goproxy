package trojan

import (
	"bytes"
	"github.com/koomox/goproxy/socks"
)

var (
	CRLF = []byte{0x0D, 0x0A}
)

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      byte = 0x01
	CmdUDPAssociate byte = 0x03
)

const (
	frameOffsetPassword = 56
	frameOffsetType     = 58
	frameOffsetAddr     = 59
)

type Request struct {
	password  []byte
	addr      []byte
	payload   []byte
	udpEnable bool
}

func EncodePacket(password, addr, payload []byte, udpEnable bool) []byte {
	if password == nil || addr == nil {
		return nil
	}
	if udpEnable && payload == nil {
		return nil
	}

	addrLen := len(addr)
	payloadLen := 0
	if payload != nil {
		payloadLen = len(payload)
	}
	reqLen := len(password) + 2 + 1 + addrLen + 2 + payloadLen
	if udpEnable {
		reqLen += 2
	}

	req := make([]byte, reqLen)
	copy(req, password)
	copy(req[frameOffsetPassword:], CRLF)
	if !udpEnable {
		req[frameOffsetType] = CmdConnect
	} else {
		req[frameOffsetType] = CmdUDPAssociate
	}
	copy(req[frameOffsetAddr:], addr)
	offset := frameOffsetAddr + addrLen
	if udpEnable {
		req[offset] = byte(payloadLen >> 8)
		req[offset+1] = byte(payloadLen)
		offset += 2
	}
	copy(req[offset:], CRLF)
	offset += 2
	if payload != nil {
		copy(req[offset:], payload)
	}

	return req
}

func EncodeUdpPacket(addr, payload []byte) []byte {
	if addr == nil || payload == nil {
		return nil
	}

	addrLen := len(addr)
	payloadLen := len(payload)
	b := make([]byte, addrLen+2+2+payloadLen)
	copy(b, addr)
	offset := addrLen
	b[offset] = byte(payloadLen >> 8)
	b[offset+1] = byte(payloadLen)
	offset += 2
	copy(b[offset:], CRLF)
	offset += 2
	copy(b[offset:], payload)

	return b
}

func ParsePacket(b []byte) (addr, payload []byte) {
	address := socks.SplitAddr(b)
	if address == nil {
		return
	}

	addrLen := len(address)
	n := len(b)
	offset := addrLen
	if n < offset+2+2 {
		return
	}

	payloadLen := int(b[offset])<<8 | int(b[offset+1])
	offset += 2
	br := b[offset:]
	if !bytes.Equal(br[:2], CRLF) {
		return
	}

	offset += 2
	buffer := b[offset:]
	bufferLen := len(buffer)
	if bufferLen >= payloadLen {
		payload = buffer[:payloadLen]
		addr = address
	}

	return
}
