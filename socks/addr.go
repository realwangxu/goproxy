package socks

import (
	"net"
	"strconv"
)

type Addr []byte

// SplitAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func SplitAddr(b []byte) Addr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case AtypIPv6:
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil

	}

	if len(b) < addrLen {
		return nil
	}

	return b[:addrLen]
}

// ParseAddr parses the address in string s. Returns nil if failed.
func ParseAddr(s string) Addr {
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return nil
	}

	var (
		addr    Addr
		addrLen int
		hostLen int
	)

	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			addrLen = 1 + net.IPv4len + 2
			addr = make([]byte, addrLen)
			addr[0] = AtypIPv4
			copy(addr[1:], ip4)
		} else {
			addrLen = 1 + net.IPv6len + 2
			addr = make([]byte, addrLen)
			addr[0] = AtypIPv6
			copy(addr[1:], ip)
		}
	} else {
		hostLen = len(host)
		if hostLen > 255 {
			return nil
		}
		addrLen = 1 + 1 + hostLen + 2
		addr = make([]byte, addrLen)
		addr[0] = AtypDomainName
		addr[1] = byte(hostLen)
		copy(addr[2:], host)
	}

	addr[addrLen-2] = byte(port >> 8)
	addr[addrLen-1] = byte(port & 0xFF)
	return addr
}

func (addr Addr) Parse() (addrType byte, host, port string) {
	var prefixLen int
	addrType = addr[0]
	switch addrType {
	case AtypIPv4:
		prefixLen = 1 + net.IPv4len
		host = net.IP(addr[1:prefixLen]).String()
		port = strconv.Itoa((int(addr[prefixLen]) << 8) | int(addr[prefixLen+1]))
	case AtypIPv6:
		prefixLen = 1 + net.IPv6len
		host = net.IP(addr[1:prefixLen]).String()
		port = strconv.Itoa((int(addr[prefixLen]) << 8) | int(addr[prefixLen+1]))
	case AtypDomainName:
		prefixLen = 2 + int(addr[1])
		host = string(addr[2:prefixLen])
		port = strconv.Itoa((int(addr[prefixLen]) << 8) | int(addr[prefixLen+1]))
	}

	return
}

func Parse(address string) (addrType byte, host, port string, err error) {
	if host, port, err = net.SplitHostPort(address); err != nil {
		return
	}

	ip := net.ParseIP(host)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			addrType = AtypIPv4
		} else {
			addrType = AtypIPv6
		}
	} else {
		addrType = AtypDomainName
	}

	return
}
