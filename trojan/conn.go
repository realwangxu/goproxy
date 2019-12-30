package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/koomox/goproxy/socks"
	"io"
	"net"
)

func Dial(addr string, tlsCfg *tls.Config, payload []byte) (net.Conn, error) {
	conn, err := tls.Dial("tcp", addr, tlsCfg)

	if err != nil {
		return nil, fmt.Errorf("tls dial failed %v", err.Error())
	}

	if _, err = conn.Write(payload); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls dial remote write failed %v", err.Error())
	}

	return conn, nil
}

// +------+----------+----------+--------+---------+----------+
//| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
//+------+----------+----------+--------+---------+----------+
//|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
//+------+----------+----------+--------+---------+----------+
// UDP ASSOCIATE
func ParseUDP(b []byte, c net.Conn) (address string, payload, buf []byte, err error) {
	addr := socks.SplitAddr(b)
	if addr == nil {
		err = errors.New("parse failed socks addr err")
		return
	}
	offset := len(addr)
	n := len(b)
	if n < offset+2+2 {
		err = errors.New("parse failed short packet")
		return
	}

	payloadLen := int(b[offset])<<8 | int(b[offset+1])
	offset += 2
	br := b[offset:]
	if !bytes.Equal(br[:2], CRLF) {
		err = errors.New("parse failed not found CRLF")
		return
	}
	offset += 2
	buffer := b[offset:]
	bufferLen := len(buffer)
	if bufferLen < payloadLen {
		payload = make([]byte, payloadLen)
		copy(payload, buffer)
		if _, err = io.ReadFull(c, payload[bufferLen:]); err != nil {
			return
		}
		return
	}
	if bufferLen > payloadLen {
		payload = buffer[:payloadLen]
		buf = buffer[payloadLen:]
		return
	}

	_, host, port := addr.Parse()
	address = net.JoinHostPort(host, port)
	payload = buffer
	return
}
