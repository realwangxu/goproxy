package socks

import (
	"io"
	"net"
)

func OnceAccept(first byte, rw io.ReadWriter) (addr Addr, err error) {
	return OnceHandshake(first, rw)
}

func Accept(rw io.ReadWriter) (addr Addr, err error) {
	return Handshake(rw)
}

// src of proxy address, dst of dest address, return proxy net.Conn interface
func Dial(dst, src string) (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", src)
	if err != nil {
		return
	}
	if _, err = conn.Write([]byte{Version5, 1, 0}); err != nil {
		return
	}
	buf := make([]byte, MaxAddrLen)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if n < 2 {
		err = ErrGeneralFailure
		return
	}
	ver := buf[0]
	method := buf[1]
	if ver != Version5 {
		err = ErrSocksVersion
		return
	}
	if method != 0 {
		err = ErrGeneralFailure
		return
	}

	raddr := ParseAddr(dst)
	if _, err = conn.Write(append([]byte{Version5, 1, 0}, raddr...)); err != nil {
		return
	}
	n, err = conn.Read(buf)
	if err != nil {
		return
	}
	if n < 2 {
		err = ErrGeneralFailure
		return
	}
	ver = buf[0]
	if ver != Version5 {
		err = ErrSocksVersion
		return
	}
	rep := buf[1]
	if rep != 0 {
		err = ErrGeneralFailure
		return
	}

	return
}
