package socks

import (
	"io"
	"net"
)

func OnceHandshake(first byte, rw io.ReadWriter) (addr Addr, err error) {
	b := make([]byte, MaxAddrLen)
	b[0] = first
	// read NMETHODS
	if _, err = io.ReadFull(rw, b[1:2]); err != nil {
		return
	}

	return handShake(b, rw) // skip VER, CMD, RSV fields
}

func Handshake(rw io.ReadWriter) (addr Addr, err error) {
	b := make([]byte, MaxAddrLen)

	// read VER, NMETHODS
	if _, err := io.ReadFull(rw, b[:2]); err != nil {
		return nil, err
	}

	return handShake(b, rw) // skip VER, CMD, RSV fields
}

func handShake(b []byte, rw io.ReadWriter) (addr Addr, err error) {
	ver := b[0]
	if ver != Version5 {
		err = ErrSocksVersion
		return
	}

	nmethods := b[1]
	// read METHODS
	if _, err = io.ReadFull(rw, b[:nmethods]); err != nil {
		return
	}

	// write VER METHOD
	if _, err = rw.Write([]byte{Version5, 0}); err != nil {
		return
	}

	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err = io.ReadFull(rw, b[:3]); err != nil {
		return
	}

	ver = b[0]
	if ver != Version5 {
		err = ErrSocksVersion
		return
	}
	cmd := b[1]
	addr, err = readAddr(rw)
	if err != nil {
		return
	}

	switch cmd {
	case CmdConnect:
		_, err = rw.Write([]byte{Version5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // SOCKS v5, reply succeeded
	case CmdUDPAssociate:
		listenAddr := ParseAddr(rw.(net.Conn).LocalAddr().String())
		_, err = rw.Write(append([]byte{Version5, 0, 0}, listenAddr...)) // SOCKS v5, reply succeeded
		if err != nil {
			return
		}
		err = InfoUDPAssociate
	default:
		err = ErrCommandNotSupported
	}

	return // skip VER, CMD, RSV fields
}

func readAddr(r io.Reader) (raw []byte, err error) {
	buf := make([]byte, MaxAddrLen)
	if _, err = io.ReadFull(r, buf[:1]); err != nil {
		return
	}

	var (
		addrType byte
		addrLen  int
	)
	addrType = buf[0]
	switch addrType {
	case AtypDomainName:
		if _, err = io.ReadFull(r, buf[1:2]); err != nil {
			return
		}
		addrLen = 2 + int(buf[1]) + 2
		if _, err = io.ReadFull(r, buf[2:addrLen]); err != nil {
			return
		}

		raw = buf[:addrLen]
	case AtypIPv4:
		addrLen = 1 + net.IPv4len + 2
		if _, err = io.ReadFull(r, buf[1:addrLen]); err != nil {
			return
		}
		raw = buf[:addrLen]
	case AtypIPv6:
		addrLen = 1 + net.IPv6len + 2
		if _, err = io.ReadFull(r, buf[1:addrLen]); err != nil {
			return
		}
		raw = buf[:addrLen]
	default:
		err = ErrAddressNotSupported
	}

	return
}
