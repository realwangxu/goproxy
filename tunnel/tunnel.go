package tunnel

import (
	"net"
)

type Conn interface {
	net.Conn
	Metadata() *Metadata
}

type PacketConn interface {
	net.PacketConn
	WriteWithMetadata([]byte, *Metadata) (int, error)
	ReadWithMetadata([]byte) (int, *Metadata, error)
}
