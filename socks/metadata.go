package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	IPv4       byte = 0x01
	DomainName byte = 0x03
	IPv6       byte = 0x04
)

type Address struct {
	DomainName  string
	Port        int
	NetworkType string
	AddressType byte
	net.IP
}

type Metadata struct {
	Command byte
	*Address
}

func (r *Metadata) ReadFrom(reader io.Reader) (err error) {
	b := [1]byte{}
	if _, err = io.ReadFull(reader, b[:]); err != nil {
		return err
	}
	r.Command = b[0]
	r.Address = &Address{}
	if err = r.Address.ReadFrom(reader); err != nil {
		return fmt.Errorf("failed to read address %v", err.Error())
	}
	return
}

func (r *Metadata) WriteTo(w io.Writer) (err error) {
	buf := bytes.NewBuffer(make([]byte, 0, 64))
	buf.WriteByte(r.Command)
	if err = r.Address.WriteTo(buf); err != nil {
		return
	}
	r.Address.NetworkType = "tcp"
	_, err = w.Write(buf.Bytes())
	return
}

func (r *Metadata) AddrType() byte {
	return r.AddressType
}

func (r *Metadata) Port() string {
	return fmt.Sprintf("%d", r.Address.Port)
}

func (r *Metadata) Host() string {
	return r.Address.Host()
}

func (r *Metadata) Network() string {
	return r.Address.Network()
}

func (r *Metadata) String() string {
	return r.Address.String()
}

func (a *Address) String() string {
	switch a.AddressType {
	case IPv4:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	case IPv6:
		return fmt.Sprintf("[%s]:%d", a.IP.String(), a.Port)
	case DomainName:
		return fmt.Sprintf("%s:%d", a.DomainName, a.Port)
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (a *Address) Host() string {
	switch a.AddressType {
	case IPv4, IPv6:
		return a.IP.String()
	case DomainName:
		return a.DomainName
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (r *Address) Network() string {
	return r.NetworkType
}

func NewAddressFromAddr(network string, addr string) (*Address, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseInt(p, 10, 32)
	if err != nil {
		return nil, err
	}
	return NewAddressFromHostPort(network, host, int(port)), nil
}

func NewAddressFromHostPort(network string, host string, port int) *Address {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return &Address{
				IP:          ip,
				Port:        port,
				AddressType: IPv4,
				NetworkType: network,
			}
		}
		return &Address{
			IP:          ip,
			Port:        port,
			AddressType: IPv6,
			NetworkType: network,
		}
	}
	return &Address{
		DomainName:  host,
		Port:        port,
		AddressType: DomainName,
		NetworkType: network,
	}
}

func (r *Address) ReadFrom(reader io.Reader) (err error) {
	b := make([]byte, 512)
	offset := 1
	if _, err = io.ReadFull(reader, b[:1]); err != nil {
		return fmt.Errorf("unable to read ATYP %v", err.Error())
	}
	r.AddressType = b[0]
	switch r.AddressType {
	case IPv4:
		offset += net.IPv4len
		if _, err = io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv4 %v", err.Error())
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case IPv6:
		offset += net.IPv6len
		if _, err = io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv6 %v", err.Error())
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case DomainName:
		offset += 1
		if _, err = io.ReadFull(reader, b[1:offset]); err != nil {
			return fmt.Errorf("failed to read domain name length")
		}
		offset += int(b[1])
		if _, err = io.ReadFull(reader, b[2:offset+2]); err != nil {
			return fmt.Errorf("failed to read domain name %v", err.Error())
		}
		r.DomainName = string(b[2:offset])
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		if ip := net.ParseIP(r.DomainName); ip != nil {
			r.IP = ip
			if ip.To4() != nil {
				r.AddressType = IPv4
			} else {
				r.AddressType = IPv6
			}
		}
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}
	return
}

func (r *Address) WriteTo(w io.Writer) (err error) {
	if _, err = w.Write([]byte{r.AddressType}); err != nil {
		return
	}
	switch r.AddressType {
	case DomainName:
		if _, err = w.Write([]byte{byte(len(r.DomainName))}); err != nil {
			return
		}
		if _, err = w.Write([]byte(r.DomainName)); err != nil {
			return
		}
	case IPv4:
		if _, err = w.Write(r.IP.To4()); err != nil {
			return
		}
	case IPv6:
		if _, err = w.Write(r.IP.To16()); err != nil {
			return
		}
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}
	port := [2]byte{}
	binary.BigEndian.PutUint16(port[:], uint16(r.Port))
	_, err = w.Write(port[:])
	return
}
