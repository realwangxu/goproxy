package trojan

var (
	CRLF = []byte{0x0D, 0x0A}
)

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      byte = 0x01
	CmdUDPAssociate byte = 0x03
)

const (
	passwordPrefixLen = 56
	cmdPrefixLen      = 58
	addrPrefixLen     = 59
)

type Request struct {
	password  []byte
	addr      []byte
	payload   []byte
	udpEnable bool
}

func EncodePacket(password, addr, payload []byte, udpEnable bool) []byte {
	pwdLen := len(password)
	addrLen := len(addr)
	prefixLen := addrPrefixLen + addrLen
	payloadLen := 0
	if payload != nil {
		payloadLen = len(payload)
	}
	var req []byte
	if !udpEnable {
		req = make([]byte, pwdLen+addrLen+payloadLen+2+1+2) // CRLF, CRLF, TCP
		req[cmdPrefixLen] = CmdConnect
	} else {
		req = make([]byte, pwdLen+addrLen+payloadLen+2+1+2+2) // CRLF, CRLF, TCP, length
		req[cmdPrefixLen] = CmdUDPAssociate
		req[prefixLen] = byte(payloadLen >> 8)
		req[prefixLen+1] = byte(payloadLen)
		prefixLen += 2
	}

	copy(req, password)
	copy(req[passwordPrefixLen:], CRLF)
	copy(req[addrPrefixLen:], addr)
	copy(req[prefixLen:], CRLF)
	if payload != nil {
		copy(req[prefixLen+2:], payload)
	}

	return req
}
