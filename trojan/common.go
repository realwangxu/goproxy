package trojan

import (
	"crypto/sha256"
	"encoding/hex"
)

var (
	CRLF = []byte{0x0D, 0x0A}
)

const (
	Connect   byte = 0x01
	Associate byte = 0x03

	MaxPacketSize = 8 * 1024
)

const (
	ActionAccept  byte = 0x01
	ActionProxy   byte = 0x02
	ActionReject  byte = 0x03
	ActionDirect  byte = 0x04
	ActionForward byte = 0x05
)

func Sha224(b []byte) []byte {
	h := sha256.New224()
	h.Write(b)
	src := h.Sum(nil)
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}
