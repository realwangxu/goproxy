package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	TypeIPv4   byte = 0x01
	TypeDomain byte = 0x03
	TypeIPv6   byte = 0x04

	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUDPAssociate byte = 0x03

	IPv4len   int = 1 + net.IPv4len + 2
	IPv6len   int = 1 + net.IPv6len + 2
	DomainLen int = 1 + 1 + 2
)

type Address struct {
	Domain      string
	Port        int
	NetworkType string
	Length      int
	AddressType byte
	net.IP
}

type Metadata struct {
	Command byte
	*Address
}

func (r *Address) String() string {
	switch r.AddressType {
	case TypeIPv4:
		return fmt.Sprintf("%s:%d", r.IP.String(), r.Port)
	case TypeIPv6:
		return fmt.Sprintf("[%s]:%d", r.IP.String(), r.Port)
	case TypeDomain:
		return fmt.Sprintf("%s:%d", r.Domain, r.Port)
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (r *Address) Network() string {
	return r.NetworkType
}

func (r *Metadata) Network() string {
	return r.Address.Network()
}

func (r *Metadata) String() string {
	return r.Address.String()
}

func (r *Address) ReadFrom(reader io.Reader) error {
	b := make([]byte, 259)
	offset := 1
	if _, err := io.ReadFull(reader, b[:1]); err != nil {
		return fmt.Errorf("unable to read ATYP %v", err.Error())
	}
	r.AddressType = b[0]
	switch r.AddressType {
	case TypeIPv4:
		offset += net.IPv4len
		if _, err := io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv4 %v", err.Error())
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		r.Length = IPv4len
	case TypeIPv6:
		offset += net.IPv6len
		if _, err := io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv6 %v", err.Error())
		}
		r.IP = b[1:offset]
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		r.Length = IPv6len
	case TypeDomain:
		offset += 1
		if _, err := io.ReadFull(reader, b[1:offset]); err != nil {
			return fmt.Errorf("failed to read domain name length")
		}
		offset += int(b[1])
		if _, err := io.ReadFull(reader, b[2:offset+2]); err != nil {
			return fmt.Errorf("failed to read domain name")
		}
		r.Domain = string(b[2:offset])
		r.Port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		r.Length = offset + 2
		if ip := net.ParseIP(r.Domain); ip != nil {
			r.IP = ip
			if ip.To4() != nil {
				r.AddressType = TypeIPv4
				r.Length = IPv4len
			} else {
				r.AddressType = TypeIPv6
				r.Length = IPv6len
			}
		}
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}

	return nil
}

func (r *Metadata) ReadFrom(reader io.Reader) error {
	b := [1]byte{}
	if _, err := io.ReadFull(reader, b[:]); err != nil {
		return err
	}
	r.Command = b[0]
	r.Address = &Address{}
	if err := r.Address.ReadFrom(reader); err != nil {
		return fmt.Errorf("failed to marshal address %v", err.Error())
	}

	return nil
}

func (r *Address) WriteTo(w io.Writer) error {
	b := make([]byte, r.Length)
	b[0] = r.AddressType

	switch r.AddressType {
	case TypeDomain:
		b[1] = byte(len(r.Domain))
		copy(b[2:], r.Domain)
	case TypeIPv4:
		copy(b[1:], r.IP.To4())
	case TypeIPv6:
		copy(b[1:], r.IP.To16())
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}

	binary.BigEndian.PutUint16(b[r.Length-2:], uint16(r.Port))

	_, err := w.Write(b[:])
	return err
}

func (r *Metadata) WriteTo(w io.Writer) error {
	b := bytes.NewBuffer(make([]byte, 1+r.Address.Length))
	b.WriteByte(r.Command)
	if err := r.Address.WriteTo(b); err != nil {
		return err
	}

	r.Address.NetworkType = "tcp"
	if _, err := w.Write(b.Bytes()); err != nil {
		return err
	}

	return nil
}

func FromHostPort(network, host string, port int) *Address {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return &Address{
				IP:          ip,
				Port:        port,
				AddressType: TypeIPv4,
				NetworkType: network,
				Length:      IPv4len,
			}
		}
		return &Address{
			IP:          ip,
			Port:        port,
			AddressType: TypeIPv6,
			NetworkType: network,
			Length:      IPv6len,
		}
	}

	return &Address{
		Domain:      host,
		Port:        port,
		AddressType: TypeDomain,
		NetworkType: network,
		Length:      DomainLen + len(host),
	}
}

func FromAddr(network, addr string) (*Address, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseInt(p, 10, 32)
	if err != nil {
		return nil, err
	}
	return FromHostPort(network, host, int(port)), nil
}
