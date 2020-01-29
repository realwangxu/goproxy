package trojan

import (
	"bytes"
	"errors"
	"github.com/koomox/goproxy/socks"
	"io"
	"net"
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

func Generate(password, addr, payload []byte, cmd byte) []byte {
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

func ParseUDPPacket(b []byte, c net.Conn) (addr, payload, buffered []byte, err error) {
	var (
		buf    []byte
		buffer []byte
		n      int
	)
	if b == nil {
		buf = make([]byte, socks.UdpBufSize)
		n, err = c.Read(buf)
		if err != nil {
			return
		}
		b = buf[:n]
	}
	buffer = b
	addr = socks.SplitAddr(buffer)
	if addr == nil {
		err = errors.New("parse address failed!")
		return
	}

	addrLen := len(addr)
	buffer = b[addrLen:]
	bLen := len(buffer)
	if bLen < 4 {
		buf = make([]byte, socks.UdpBufSize)
		n, err = c.Read(buf[bLen:])
		if err != nil {
			return
		}
		copy(buf, buffer)
		buffer = buf[:bLen+n]
		bLen = len(buffer)
		if bLen < 4 {
			err = errors.New("udp packet short")
			return
		}
	}

	payloadLen := int(buffer[0])<<8 | int(buffer[1])
	buffer = buffer[2:]
	if !bytes.Equal(buffer[:2], CRLF) {
		err = errors.New("parse udp packet not found CRLF")
		return
	}

	buffer = buffer[2:]
	bLen = len(buffer)
	if bLen < payloadLen {
		buf = make([]byte, payloadLen)
		n, err = io.ReadFull(c, buf[bLen:])
		if err != nil {
			return
		}
		copy(buf, buffer)
		buffer = buf[:bLen+n]
		bLen = len(buffer)
		if bLen < payloadLen {
			err = errors.New("udp packet short")
			return
		}
	}

	payload = buffer[:payloadLen]
	if bLen > payloadLen {
		buf = buffer[payloadLen:]
		buffered = make([]byte, len(buf))
		copy(buffered, buf)
	}

	return
}
