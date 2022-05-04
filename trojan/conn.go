package trojan

import (
	"bytes"
	"net"
)

type Conn struct {
	net.Conn
	hash     string
	metadata *Metadata
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) Metadata() *Metadata {
	return c.metadata
}

func (c *Conn) Hash() string {
	return c.hash
}

func (c *Conn) WriteHeader(b []byte) (int, error) {
	buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
	buf.WriteString(c.hash)
	buf.Write(CRLF)
	c.metadata.WriteTo(buf)
	buf.Write(CRLF)
	if b != nil {
		buf.Write(b)
	}
	return c.Conn.Write(buf.Bytes())
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}
