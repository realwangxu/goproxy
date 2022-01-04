package socks

import (
	"io"
	"net"
)

func OnceHandshake(first byte, rw io.ReadWriter) (addr *Address, err error) {
	b := make([]byte, MaxAddrLen)
	b[0] = first
	// read NMETHODS
	if _, err = io.ReadFull(rw, b[1:2]); err != nil {
		return
	}

	return handShake(b, rw) // skip VER, CMD, RSV fields
}

func Handshake(rw io.ReadWriter) (addr *Address, err error) {
	b := make([]byte, MaxAddrLen)

	// read VER, NMETHODS
	if _, err := io.ReadFull(rw, b[:2]); err != nil {
		return nil, err
	}

	return handShake(b, rw) // skip VER, CMD, RSV fields
}

func handShake(b []byte, rw io.ReadWriter) (addr *Address, err error) {
	var (
		lAddr *Address
	)
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
	addr = &Address{}
	if err = addr.ReadFrom(rw); err != nil {
		return
	}
	switch cmd {
	case CmdConnect:
		_, err = rw.Write([]byte{Version5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // SOCKS v5, reply succeeded
	case CmdUDPAssociate:
		if lAddr, err = FromAddr(rw.(net.Conn).LocalAddr().String()); err != nil {
			return
		}
		listenAddr := lAddr.Bytes()
		if _, err = rw.Write(append([]byte{Version5, 0, 0}, listenAddr...)); err != nil {
			return
		}
		err = InfoUDPAssociate
	default:
		err = ErrCommandNotSupported
	}

	return // skip VER, CMD, RSV fields
}
