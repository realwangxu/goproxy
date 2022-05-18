package trojan

import (
	"crypto/sha256"
	"encoding/hex"
)

func Sha224(b []byte) []byte {
	h := sha256.New224()
	h.Write(b)
	src := h.Sum(nil)
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}
