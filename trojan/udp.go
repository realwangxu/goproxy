package trojan

import (
	"bytes"
	"github.com/koomox/goproxy/socks"
	"net"
)

type UDPPacket struct {
	buf     []byte
	addr    []byte
	payload []byte
	buffer  []byte
}

func NewUDPPacket() *UDPPacket {
	return &UDPPacket{}
}

func (h *UDPPacket) Bytes() []byte {
	return h.buf
}

func (h *UDPPacket) Addr() []byte {
	return h.addr
}

func (h *UDPPacket) String() string {
	if h.addr == nil {
		return ""
	}
	addr := socks.SplitAddr(h.addr)
	if addr == nil {
		return ""
	}
	_, host, port := addr.Parse()
	return net.JoinHostPort(host, port)
}

func (h *UDPPacket) Payload() []byte {
	return h.payload
}

func (h *UDPPacket) Buffer() []byte {
	return h.buffer
}

func (h *UDPPacket) Generate(addr, payload []byte) {
	var buf bytes.Buffer
	h.addr = addr
	h.payload = payload
	buf.Write(addr)
	payloadLen := len(payload)
	buf.WriteByte(byte(payloadLen >> 8))
	buf.WriteByte(byte(payloadLen & 0xFF))
	buf.Write(CRLF)
	buf.Write(payload)
	h.buf = buf.Bytes()
}

func (h *UDPPacket) Parse(buf []byte) bool {
	h.buf = buf
	address := socks.SplitAddr(buf)
	if address == nil {
		return false
	}

	bufLen := len(buf)
	offset := len(address)
	h.addr = buf[:offset]
	if bufLen <= offset+4 {
		return false
	}
	payloadLen := int(buf[offset])<<8 | int(buf[offset+1])
	offset += 2
	br := buf[offset:]
	if !bytes.Equal(br[:2], CRLF) {
		return false
	}
	offset += 2
	fullLen := offset + payloadLen
	if bufLen < fullLen {
		return false
	}
	h.payload = buf[offset:fullLen]
	if bufLen > fullLen {
		h.buffer = buf[fullLen:]
	}

	return true
}
