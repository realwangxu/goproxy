package trojan

import (
	"crypto/sha256"
	"encoding/hex"
)

func HexSha224(b []byte) []byte {
	h := sha256.New224()
	h.Write(b)
	src := h.Sum(nil)
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

func HexSha224ToString(b []byte) string {
	h := sha256.New224()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
