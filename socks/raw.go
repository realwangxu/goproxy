package socks

import (
	"io"
	"net"
	"strconv"
)

type RawAddr struct {
	Atyp byte
	Host string // Ipv4、Ipv6、Domain
	Port string
	Addr string // host:port
	Buf  []byte
}

func (this *RawAddr) String() string {
	if this.Addr == "" {
		this.addr()
	}
	return this.Addr
}

func (this *RawAddr) RawAddr() []byte {
	return this.Buf
}

func (this *RawAddr) addr() {
	if this.Addr != "" {
		return
	}
	switch this.Atyp {
	case AtypDomainName:
		this.Host = string(this.Buf[2 : 2+int(this.Buf[1])])
		this.Port = strconv.Itoa((int(this.Buf[2+int(this.Buf[1])]) << 8) | int(this.Buf[2+int(this.Buf[1])+1]))
	case AtypIPv4:
		this.Host = net.IP(this.Buf[1 : 1+net.IPv4len]).String()
		this.Port = strconv.Itoa((int(this.Buf[1+net.IPv4len]) << 8) | int(this.Buf[1+net.IPv4len+1]))
	case AtypIPv6:
		this.Host = net.IP(this.Buf[1 : 1+net.IPv6len]).String()
		this.Port = strconv.Itoa((int(this.Buf[1+net.IPv6len]) << 8) | int(this.Buf[1+net.IPv6len+1]))
	}

	this.Addr = net.JoinHostPort(this.Host, this.Port)
}

func ReadRawAddr(r io.Reader) (*RawAddr, error) {
	return readRawAddr(r)
}

func readRawAddr(r io.Reader) (*RawAddr, error) {
	buf := make([]byte, MaxAddrLen)

	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return nil, err
	}

	addrType := buf[0]

	switch addrType {
	case AtypDomainName:
		if _, err := io.ReadFull(r, buf[1:2]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, buf[2:2+int(buf[1])+2]); err != nil {
			return nil, err
		}
		return &RawAddr{Atyp: AtypDomainName, Buf: buf[:1+1+int(buf[1])+2]}, nil
	case AtypIPv4:
		if _, err := io.ReadFull(r, buf[1:1+net.IPv4len+2]); err != nil {
			return nil, err
		}
		return &RawAddr{Atyp: AtypIPv4, Buf: buf[:1+net.IPv4len+2]}, nil
	case AtypIPv6:
		if _, err := io.ReadFull(r, buf[1:1+net.IPv6len+2]); err != nil {
			return nil, err
		}
		return &RawAddr{Atyp: AtypIPv6, Buf: buf[:1+net.IPv6len+2]}, nil
	}

	return nil, ErrAddressNotSupported
}
