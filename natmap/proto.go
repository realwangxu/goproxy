package natmap

type mode int

const (
	RemoteServer mode = iota
	RelayClient
	SocksClient
)

const udpBufSize = 64 * 1024
