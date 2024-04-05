package tcpproxy

import (
	"bufio"
	"bytes"
)

func (p *Proxy) AddPrefixRoute(ipPort string, prefix []byte, dest Target) {
	p.addRoute(ipPort, prefixMatch{prefix: prefix, target: dest})
}

type prefixMatch struct {
	prefix []byte
	target Target
}

func (p prefixMatch) match(br *bufio.Reader) (Target, string) {
	if len(p.prefix) == 0 {
		return nil, ""
	}
	b, err := br.Peek(len(p.prefix))
	if err != nil {
		return nil, ""
	}
	if bytes.Equal(b, p.prefix) {
		return p.target, ""
	}
	return nil, ""
}
