package socks

import "time"

func (this *handle) UpdateTicker() {
	ticker := time.NewTicker(time.Second * 60) // Minute

	for {
		select {
		case <-ticker.C:
			this.handlerTicker()
		}
	}
}

func (this *handle) handlerTicker() {
	this.run()
}
