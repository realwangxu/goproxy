package socks

import "time"

func (r *Server) UpdateTicker(d time.Duration) {
	r.handlerTicker()
	time.AfterFunc(d, func() { r.UpdateTicker(d) })
}

func (r *Server) handlerTicker() {
	r.run()
}