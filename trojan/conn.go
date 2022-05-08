package trojan

import (
	"bytes"
	"fmt"
	"net"
	"sync"
)

type Conn interface {
	net.Conn
	Metadata() *Metadata
}

type OutboundConn struct {
	net.Conn
	hash              string
	metadata          *Metadata
	headerWrittenOnce sync.Once
}

func (c *OutboundConn) Close() error {
	return c.Conn.Close()
}

func (c *OutboundConn) Metadata() *Metadata {
	return c.metadata
}

func (c *OutboundConn) Hash() string {
	return c.hash
}

func (c *OutboundConn) WriteHeader(payload []byte) (bool, error) {
	var err error
	written := false
	c.headerWrittenOnce.Do(func() {
		buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
		buf.WriteString(c.hash)
		buf.Write(CRLF)
		c.metadata.WriteTo(buf)
		buf.Write(CRLF)
		if payload != nil {
			buf.Write(payload)
		}
		_, err = c.Conn.Write(buf.Bytes())
		if err == nil {
			written = true
		}
	})
	return written, err
}

func (c *OutboundConn) Write(p []byte) (int, error) {
	written, err := c.WriteHeader(p)
	if err != nil {
		return 0, fmt.Errorf("trojan failed to flush header with payload")
	}
	if written {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *OutboundConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

type InboundConn struct {
	net.Conn
	hash     string
	metadata *Metadata
}

func (c *InboundConn) Close() error {
	return c.Conn.Close()
}

func (c *InboundConn) Metadata() *Metadata {
	return c.metadata
}

func (c *InboundConn) Hash() string {
	return c.hash
}

func (c *InboundConn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *InboundConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}
