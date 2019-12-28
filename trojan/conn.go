package trojan

import (
	"crypto/tls"
	"fmt"
	"net"
)

func Dial(addr string, tlsCfg *tls.Config, raw, secret, payload []byte, udpEnable bool) (net.Conn, error) {
	conn, err := tls.Dial("tcp", addr, tlsCfg)

	if err != nil {
		return nil, fmt.Errorf("tls dial failed %v", err.Error())
	}

	if _, err = conn.Write(EncodePacket(secret, raw, payload, udpEnable)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls dial remote write failed %v", err.Error())
	}

	return conn, nil
}
