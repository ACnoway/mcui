package xrayconfig

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// PublicListenAddress is reserved for the node-local ingress proxy inside
// the Xray network namespace.
const PublicListenAddress = "127.0.0.2"

const publicTagPrefix = "published-"

type PublicEndpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (e PublicEndpoint) Valid() bool {
	return e.Port > 0 && e.Port <= 65535 && publicIPv4(e.Address)
}

func (e PublicEndpoint) String() string {
	return net.JoinHostPort(e.Address, strconv.Itoa(e.Port))
}

func Publishable(protocol string) bool {
	return protocol == Trojan || protocol == VLESSReality
}

// PublishedEndpoint reads the public endpoint bound into an Xray inbound tag.
func PublishedEndpoint(tag string) (PublicEndpoint, bool) {
	value, ok := strings.CutPrefix(tag, publicTagPrefix)
	if !ok {
		return PublicEndpoint{}, false
	}
	addr, err := netip.ParseAddrPort(value)
	if err != nil || !addr.Addr().Is4() || addr.String() != value {
		return PublicEndpoint{}, false
	}
	endpoint := PublicEndpoint{Address: addr.Addr().String(), Port: int(addr.Port())}
	return endpoint, endpoint.Valid()
}
