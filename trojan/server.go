package trojan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/koomox/goproxy"
	"github.com/koomox/goproxy/tunnel"
	"io"
	"net"
	"sync"
)

var (
	CRLF = []byte{0x0D, 0x0A}
)

const (
	Connect   byte = 0x01
	Associate byte = 0x03

	MaxPacketSize = 8 * 1024

	ActionAccept  byte = 0x01
	ActionProxy   byte = 0x02
	ActionReject  byte = 0x03
	ActionDirect  byte = 0x04
	ActionForward byte = 0x05
)

type Hook interface {
	Auth(string) bool
	Router(string, *tunnel.Metadata) byte
	Forward(string, *tunnel.Metadata) (net.Conn, error)
}

type Server struct {
	sync.RWMutex
	front         string
	tcpListener   net.Listener
	hook          Hook
	authenticator bool
	connChan      chan tunnel.Conn
	packetChan    chan tunnel.PacketConn
	ctx           context.Context
	cancel        context.CancelFunc
	log           goproxy.Logger
}

func NewServer(front, addr string, tlsConfig *tls.Config, ctx context.Context, log goproxy.Logger) (*Server, error) {
	ctx, cancel := context.WithCancel(ctx)
	tcpListener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create tcp listener %v %v", addr, err.Error())
	}
	s := &Server{
		front:         front,
		tcpListener:   tcpListener,
		authenticator: false,
		connChan:      make(chan tunnel.Conn, 32),
		packetChan:    make(chan tunnel.PacketConn, 32),
		ctx:           ctx,
		cancel:        cancel,
		log:           log,
	}
	log.Info("trojan server created", addr)
	go s.acceptLoop()
	return s, nil
}

func (s *Server) AddHook(hook Hook) {
	s.hook = hook
	s.authenticator = true
}

func (s *Server) Close() error {
	s.cancel()
	return s.tcpListener.Close()
}

func (s *Server) AcceptConn() (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, errors.New("trojan server closed")
	}
}

func (s *Server) AcceptPacket() (tunnel.PacketConn, error) {
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
			if !s.authenticator {
				s.log.Errorf("authenticator is not load")
				s.frontPage(c, b[:n])
				return
			}

			if n != 56 {
				s.log.Errorf("trojan failed to read hash %X", b[:n])
				s.frontPage(c, b[:n])
				return
			}
			password := string(b[:])
			if !s.hook.Auth(password) {
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

			metadata := &tunnel.Metadata{}
			if err = metadata.ReadFrom(c); err != nil {
				c.Close()
				s.log.Errorf("trojan read address error %v", err.Error())
				return
			}
			if _, err = io.ReadFull(c, crlf[:]); err != nil {
				c.Close()
				s.log.Errorf("trojan read CRLF error %v", err.Error())
				return
			}

			switch s.hook.Router(password, metadata) {
			case ActionAccept, ActionProxy:
				switch metadata.Command {
				case Connect:
					s.connChan <- &InboundConn{Conn: c, hash: password, metadata: metadata}
					s.log.Debug("trojan tcp connection")
				case Associate:
					s.packetChan <- &PacketConn{&InboundConn{Conn: c, hash: password, metadata: metadata}}
					s.log.Debug("trojan udp connection")
				default:
					c.Close()
					s.log.Errorf("unknown trojan command %v", metadata.Command)
				}
			case ActionDirect, ActionReject:
				c.Close()
				return
			case ActionForward:
				s.Forward(password, metadata, c)
			}
		}(c)
	}
}

func (s *Server) Forward(password string, metadata *tunnel.Metadata, c net.Conn) {
	defer c.Close()
	rc, err := s.hook.Forward(password, metadata)
	if err != nil {
		return
	}
	defer rc.Close()

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
			s.log.Errorf("trojan forward error %v", ch.Error())
		}
	case <-s.ctx.Done():
		s.log.Debug("trojan forward closed")
		return
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
