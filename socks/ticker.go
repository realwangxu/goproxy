package socks

import "time"

func (h *handle) UpdateTicker() {
	ticker := time.NewTicker(time.Second * 60) // Minute

	for {
		select {
		case <-ticker.C:
			h.handlerTicker()
		}
	}
}

func (h *handle) handlerTicker() {
	h.run()
	h.runUDP()
}
