package tunnel

import (
	"context"
	"fmt"
	"net"
)

type Addr interface {
	Type() byte
	Network() string
	Port() string
	Host() string
	Bytes() []byte
	String() string
}

type Conn interface {
	net.Conn
	Metadata() *Metadata
}

type PacketConn interface {
	net.PacketConn
	WriteWithMetadata([]byte, *Metadata) (int, error)
	ReadWithMetadata([]byte) (int, *Metadata, error)
}

type ConnDialer interface {
	DialConn(*Address, Tunnel) (Conn, error)
}

type PacketDialer interface {
	DialPacket(Tunnel) (PacketConn, error)
}

type ConnListener interface {
	AcceptConn(Tunnel) (Conn, error)
}

type PacketListener interface {
	AcceptPacket(Tunnel) (PacketConn, error)
}

type Dialer interface {
	ConnDialer
	PacketDialer
}

type Listener interface {
	ConnListener
	PacketListener
}

type Client interface {
	Dialer
}

type Server interface {
	Listener
}

type Tunnel interface {
	Name() string
	NewClient(context.Context, Client) (Client, error)
	NewServer(context.Context, Server) (Server, error)
}

var (
	tunnels = make(map[string]Tunnel)
)

func RegisterTunnel(name string, tunnel Tunnel) {
	tunnels[name] = tunnel
}

func GetTunnel(name string) (Tunnel, error) {
	if v, ok := tunnels[name]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("unknown tunnel name %v", name)
}
