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
	domain      string
	ip          net.IP
	host        string
	port        int
	NetworkType string
	AddressType byte
}

type Metadata struct {
	Command byte
	*Address
}

func (r *Address) String() string {
	switch r.AddressType {
	case TypeIPv4:
		return fmt.Sprintf("%s:%d", r.ip.String(), r.port)
	case TypeIPv6:
		return fmt.Sprintf("[%s]:%d", r.ip.String(), r.port)
	case TypeDomain:
		return fmt.Sprintf("%s:%d", r.domain, r.port)
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (r *Address) Network() string {
	return r.NetworkType
}

func (r *Address) Port() string {
	return fmt.Sprintf("%d", r.port)
}

func (r *Address) Host() string {
	switch r.AddressType {
	case TypeIPv4:
		return r.ip.String()
	case TypeIPv6:
		return r.ip.String()
	case TypeDomain:
		return r.domain
	default:
		return "INVALID_ADDRESS_TYPE"
	}
}

func (r *Address) Type() byte {
	return r.AddressType
}

func (r *Address) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	if err := r.WriteTo(b); err != nil {
		return nil
	}
	return b.Bytes()
}

func (r *Metadata) Network() string {
	return r.Address.Network()
}

func (r *Metadata) String() string {
	return r.Address.String()
}

func (r *Metadata) Port() string {
	return r.Address.Port()
}

func (r *Metadata) Host() string {
	return r.Address.Host()
}

func (r *Metadata) Type() byte {
	return r.Address.AddressType
}

func (r *Metadata) Bytes() []byte {
	return r.Address.Bytes()
}

func (r *Address) ReadFrom(reader io.Reader) (err error) {
	b := make([]byte, 259)
	offset := 1
	if _, err = io.ReadFull(reader, b[:1]); err != nil {
		return fmt.Errorf("unable to read ATYP %v", err.Error())
	}
	r.AddressType = b[0]
	switch r.AddressType {
	case TypeIPv4:
		offset += net.IPv4len
		if _, err = io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv4 %v", err.Error())
		}
		r.ip = b[1:offset]
		r.port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case TypeIPv6:
		offset += net.IPv6len
		if _, err = io.ReadFull(reader, b[1:offset+2]); err != nil {
			return fmt.Errorf("failed to read IPv6 %v", err.Error())
		}
		r.ip = b[1:offset]
		r.port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
	case TypeDomain:
		offset += 1
		if _, err = io.ReadFull(reader, b[1:offset]); err != nil {
			return fmt.Errorf("failed to read domain name length")
		}
		offset += int(b[1])
		if _, err = io.ReadFull(reader, b[2:offset+2]); err != nil {
			return fmt.Errorf("failed to read domain name")
		}
		r.domain = string(b[2:offset])
		r.port = int(binary.BigEndian.Uint16(b[offset : offset+2]))
		if ip := net.ParseIP(r.domain); ip != nil {
			r.ip = ip
			if ip.To4() != nil {
				r.AddressType = TypeIPv4
			} else {
				r.AddressType = TypeIPv6
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

func (r *Address) WriteTo(w io.Writer) (err error) {
	if _, err = w.Write([]byte{r.AddressType}); err != nil {
		return
	}

	switch r.AddressType {
	case TypeDomain:
		if _, err = w.Write([]byte{byte(len(r.domain))}); err != nil {
			return
		}
		if _, err = w.Write([]byte(r.domain)); err != nil {
			return
		}
	case TypeIPv4:
		if _, err = w.Write(r.ip.To4()); err != nil {
			return
		}
	case TypeIPv6:
		if _, err = w.Write(r.ip.To16()); err != nil {
			return
		}
	default:
		return fmt.Errorf("invalid ATYP %v", r.AddressType)
	}

	port := [2]byte{}
	binary.BigEndian.PutUint16(port[:], uint16(r.port))

	_, err = w.Write(port[:])
	return
}

func (r *Metadata) WriteTo(w io.Writer) (err error) {
	b := bytes.NewBuffer([]byte{})
	b.WriteByte(r.Command)
	if err = r.Address.WriteTo(b); err != nil {
		return
	}

	r.Address.NetworkType = "tcp"
	_, err = w.Write(b.Bytes())

	return
}

func FromHostPort(network, host string, port int) *Address {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return &Address{
				ip:          ip,
				port:        port,
				AddressType: TypeIPv4,
				NetworkType: network,
			}
		}
		return &Address{
			ip:          ip,
			port:        port,
			AddressType: TypeIPv6,
			NetworkType: network,
		}
	}

	return &Address{
		domain:      host,
		port:        port,
		AddressType: TypeDomain,
		NetworkType: network,
	}
}

func FromAddr(network, addr string) (*Address, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseInt(p, 10, 16)
	if err != nil {
		return nil, err
	}
	return FromHostPort(network, host, int(port)), nil
}
