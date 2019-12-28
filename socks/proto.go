package socks

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUDPAssociate byte = 0x03
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       byte = 0x01
	AtypDomainName byte = 0x03
	AtypIPv6       byte = 0x04
)

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

const (
	Version5 byte = 0x05
	Version4 byte = 0x04
)
