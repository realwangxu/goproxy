package trojan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type packetInfo struct {
	src     *Metadata
	payload []byte
}

type PacketConn struct {
	*Conn
}

func (c *PacketConn) Close() error {
	return c.Conn.Close()
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.ReadWithMetadata(b)
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	address, err := ResolveAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	return c.WriteWithMetadata(b, &Metadata{Command: Associate, Address: address})
}

func (c *PacketConn) WriteWithMetadata(b []byte, m *Metadata) (int, error) {
	packet := make([]byte, 0, MaxPacketSize)
	w := bytes.NewBuffer(packet)
	m.Address.WriteTo(w)
	length := len(b)
	buf := [2]byte{}
	binary.BigEndian.PutUint16(buf[:], uint16(length))
	w.Write(buf[:])
	w.Write(CRLF)
	w.Write(b)
	_, err := c.Conn.Write(w.Bytes())
	return len(b), err
}

func (c *PacketConn) ReadWithMetadata(b []byte) (int, *Metadata, error) {
	addr := &Address{NetworkType: "udp"}
	if err := addr.ReadFrom(c.Conn); err != nil {
		return 0, nil, fmt.Errorf("failed to parse udp packet addr %v", err.Error())
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, buf[:]); err != nil {
		return 0, nil, fmt.Errorf("failed to read length %v", err.Error())
	}
	length := int(binary.BigEndian.Uint16(buf[:2]))
	if !bytes.Equal(buf[2:], CRLF) {
		return 0, nil, fmt.Errorf("failed to read CRLF")
	}
	if len(b) < length || length > MaxPacketSize {
		buf = make([]byte, length)
		io.ReadFull(c.Conn, buf[:])
		return 0, nil, fmt.Errorf("incoming packet size is too large")
	}
	if _, err := io.ReadFull(c.Conn, b[:length]); err != nil {
		return 0, nil, fmt.Errorf("failed to read payload %v", err.Error())
	}
	return length, &Metadata{Command: Associate, Address: addr}, nil
}
