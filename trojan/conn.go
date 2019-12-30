package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"socks"
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

func Parse(b []byte, c net.Conn) (payload, buf []byte, err error) {
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
	r := n - offset - payloadLen
	if r == 0 {

	}
	if r < 0 {
		payload = make([]byte, offset+payloadLen)
		if n, err = io.ReadFull(c, payload[offset:]); err != nil {
			return
		}
		return
	}

	if r > 0 {

	}
}
