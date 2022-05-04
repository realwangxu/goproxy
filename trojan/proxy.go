package trojan

import (
	"context"
	"io"
	"net"
)

type Proxy struct {
	source *Server
	ctx    context.Context
	cancel context.CancelFunc
	log    Logger
}

func NewProxy(ctx context.Context, cancel context.CancelFunc, source *Server) *Proxy {
	return &Proxy{
		source: source,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (p *Proxy) relayConnLoop() {
	for {
		inbound, err := p.source.AcceptConn()
		if err != nil {
			select {
			case <-p.ctx.Done():
				p.log.Debug("exit")
				return
			default:
			}
			p.log.Error("failed to accept connection", err)
			continue
		}
		go func(inbound *Conn) {
			defer inbound.Close()
			outbound, err := net.Dial("tcp", "")
			if err != nil {
				p.log.Error("proxy failed to dial connection", err)
				return
			}
			defer outbound.Close()
			errChan := make(chan error, 2)
			copyConn := func(left, right net.Conn) {
				_, err := io.Copy(left, right)
				errChan <- err
			}
			go copyConn(inbound, outbound)
			go copyConn(outbound, inbound)
			select {
			case err = <-errChan:
				if err != nil {
					p.log.Error(err)
				}
			case <-p.ctx.Done():
				p.log.Debug("shutting down conn relay")
				return
			}
			p.log.Debug("conn relay ends")
		}(inbound)
	}
}
