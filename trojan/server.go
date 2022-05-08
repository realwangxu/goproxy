package trojan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

type Logger interface {
	Info(...interface{})
	Infof(string, ...interface{})
	Error(...interface{})
	Errorf(string, ...interface{})
	Debug(...interface{})
}

type Worker interface {
	Auth(string) bool
}

type Server struct {
	sync.RWMutex
	front       string
	tcpListener net.Listener
	worker      Worker
	connChan    chan Conn
	packetChan  chan PacketConn
	ctx         context.Context
	cancel      context.CancelFunc
	log         Logger
}

func NewServer(front, addr string, tlsConfig *tls.Config, worker Worker, ctx context.Context, log Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(ctx)
	tcpListener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create tcp listener %v %v", addr, err.Error())
	}
	s := &Server{
		front:       front,
		tcpListener: tcpListener,
		worker:      worker,
		connChan:    make(chan Conn, 32),
		packetChan:  make(chan PacketConn, 32),
		ctx:         ctx,
		cancel:      cancel,
		log:         log,
	}
	log.Info("trojan server created", addr)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) Close() error {
	s.cancel()
	return s.tcpListener.Close()
}

func (s *Server) AcceptConn() (Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, errors.New("trojan server closed")
	}
}

func (s *Server) AcceptPacket() (PacketConn, error) {
	select {
	case conn := <-s.packetChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, errors.New("trojan server closed")
	}
}

func (s *Server) acceptLoop() {
	for {
		c, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			s.log.Errorf("trojan accept error %v", err.Error())
			break
		}

		go func(c net.Conn) {
			b := [56]byte{}
			n, err := c.Read(b[:])
			if err != nil {
				c.Close()
				s.log.Errorf("trojan read hash error %v", err.Error())
				return
			}

			if n != 56 {
				s.log.Errorf("trojan failed to read hash %X", b[:n])
				s.frontPage(c, b[:n])
				return
			}
			password := string(b[:])
			if !s.worker.Auth(password) {
				s.log.Errorf("trojan invalid hash %v", password)
				s.frontPage(c, b[:])
				return
			}

			crlf := [2]byte{}
			if _, err = io.ReadFull(c, crlf[:]); err != nil {
				c.Close()
				s.log.Errorf("trojan read CRLF error %v", err.Error())
				return
			}

			m := &Metadata{}
			if err = m.ReadFrom(c); err != nil {
				c.Close()
				s.log.Errorf("trojan read address error %v", err.Error())
				return
			}

			if _, err = io.ReadFull(c, crlf[:]); err != nil {
				c.Close()
				s.log.Errorf("trojan read CRLF error %v", err.Error())
				return
			}
			switch m.Command {
			case Connect:
				s.connChan <- &InboundConn{Conn: c, hash: password, metadata: m}
				s.log.Debug("trojan tcp connection")
			case Associate:
				s.packetChan <- &UDPConn{&InboundConn{Conn: c, hash: password, metadata: m}}
				s.log.Debug("trojan udp connection")
			default:
				c.Close()
				s.log.Errorf("unknown trojan command %v", m.Command)
			}
		}(c)
	}
}

func (s *Server) frontPage(c net.Conn, b []byte) {
	defer c.Close()
	rc, err := net.Dial("tcp", s.front)
	if err != nil {
		return
	}
	defer rc.Close()
	if _, err = rc.Write(b); err != nil {
		return
	}

	errChan := make(chan error, 2)
	copyConn := func(left, right net.Conn) {
		_, errInfo := io.Copy(left, right)
		errChan <- errInfo
	}
	go copyConn(c, rc)
	go copyConn(rc, c)
	select {
	case ch := <-errChan:
		if ch != nil {
			s.log.Errorf("trojan relay error %v", ch.Error())
		}
	case <-s.ctx.Done():
		s.log.Debug("trojan server closed")
		return
	}
}
