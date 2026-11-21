package master

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ACnoway/mcui/internal/security"
)

type httpsProxy struct {
	origin string
	host   string
	peer   netip.Addr
}

type proxyContextKey struct{}

type proxiedRequest struct {
	origin string
	client string
}

func (s *Server) ConfigureHTTPSProxy(publicURL, address string) error {
	origin, err := security.MasterOrigin(publicURL)
	if err != nil {
		return err
	}
	peer, err := netip.ParseAddr(address)
	if err != nil || peer.Zone() != "" {
		return errors.New("HTTPS proxy peer must be a single loopback or private IP")
	}
	peer = peer.Unmap()
	if !peer.IsLoopback() && !peer.IsPrivate() {
		return errors.New("HTTPS proxy peer must be a single loopback or private IP")
	}
	host := canonicalHTTPSHost(strings.TrimPrefix(origin, "https://"))
	s.proxy = &httpsProxy{origin: "https://" + host, host: host, peer: peer}
	return nil
}

func canonicalHTTPSHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ":443")
}

func (p *httpsProxy) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		peer, parseErr := netip.ParseAddr(remote)
		proto := r.Header.Values("X-Forwarded-Proto")
		if err != nil || parseErr != nil || peer.Unmap() != p.peer || r.TLS != nil ||
			len(proto) != 1 || proto[0] != "https" || canonicalHTTPSHost(r.Host) != p.host {
			http.Error(w, "request must arrive through the configured HTTPS proxy", http.StatusForbidden)
			return
		}
		proxy := proxiedRequest{origin: p.origin}
		if forwarded := r.Header.Values("X-Forwarded-For"); len(forwarded) == 1 {
			if ip, err := netip.ParseAddr(forwarded[0]); err == nil && ip.Zone() == "" {
				proxy.client = ip.Unmap().String()
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), proxyContextKey{}, proxy)))
	})
}

func proxyRequest(r *http.Request) (proxiedRequest, bool) {
	proxy, ok := r.Context().Value(proxyContextKey{}).(proxiedRequest)
	return proxy, ok
}

func secureRequest(r *http.Request) bool {
	_, viaProxy := proxyRequest(r)
	return r.TLS != nil || viaProxy
}
