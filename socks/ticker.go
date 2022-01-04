package socks

import "time"

func (r *Server) UpdateTicker() {
	r.handlerTicker()
	time.AfterFunc(60 * time.Second, func() { r.UpdateTicker() })
}

func (r *Server) handlerTicker() {
	r.run()
}