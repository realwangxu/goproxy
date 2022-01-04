package socks

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

type Address struct {
	domain      string
	ip          net.IP
	host        string
	port        int
	AddressType byte
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

func (r *Address) AddrType() byte {
	return r.AddressType
}

func (r *Address) Bytes() []byte {
	b := bytes.NewBuffer([]byte{})
	if err := r.WriteTo(b); err != nil {
		return nil
	}
	return b.Bytes()
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

func FromHostPort(host string, port int) *Address {
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return &Address{
				ip:          ip,
				port:        port,
				AddressType: TypeIPv4,
			}
		}
		return &Address{
			ip:          ip,
			port:        port,
			AddressType: TypeIPv6,
		}
	}

	return &Address{
		domain:      host,
		port:        port,
		AddressType: TypeDomain,
	}
}

func FromAddr(addr string) (*Address, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseInt(p, 10, 16)
	if err != nil {
		return nil, err
	}
	return FromHostPort(host, int(port)), nil
}
