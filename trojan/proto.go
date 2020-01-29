package trojan

import (
	"bytes"
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

func NewRequest(password, addr, payload []byte, cmd byte) []byte {
	if password == nil || addr == nil {
		return nil
	}
	if cmd == CmdUDPAssociate && payload == nil {
		return nil
	}
	var buf bytes.Buffer
	buf.Write(password)
	buf.Write(CRLF)
	switch cmd {
	case CmdConnect:
		buf.WriteByte(CmdConnect)
	case CmdUDPAssociate:
		buf.WriteByte(CmdUDPAssociate)
	default:
		return nil
	}
	buf.Write(addr)
	payloadLen := len(payload)
	switch cmd {
	case CmdUDPAssociate:
		buf.WriteByte(byte(payloadLen >> 8))
		buf.WriteByte(byte(payloadLen & 0xFF))
	}
	buf.Write(CRLF)
	if payload != nil {
		buf.Write(payload)
	}

	return buf.Bytes()
}

func MakeRequest(password, addr, payload []byte, udpEnable bool) []byte {
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
