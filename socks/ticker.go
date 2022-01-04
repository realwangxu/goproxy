package socks

import "time"

func (r *Server) UpdateTicker() {
	ticker := time.NewTicker(time.Second * 60) // Minute

	for {
		select {
		case <-ticker.C:
			r.handlerTicker()
		}
	}
}

func (r *Server) handlerTicker() {
	r.run()
}
