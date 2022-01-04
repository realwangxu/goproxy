package socks

import "time"

func (r *Server) UpdateTicker() {
	r.handlerTicker()
	time.AfterFunc(time.Second * 60, func() { r.UpdateTicker() }) // Minute
}

func (r *Server) handlerTicker() {
	r.run()
}