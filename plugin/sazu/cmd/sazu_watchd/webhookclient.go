package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// newWebhookClient returns the HTTP client sazu-watchd POSTs webhook
// alerts with. Webhook URLs are registered by zone owners (sazuctl
// contact), not by the operator running this daemon -- and anyone who
// controls a domain can onboard it -- so an unrestricted client would
// let any zone owner make this host send requests into the hoster's own
// network: loopback services, the cloud metadata endpoint, internal
// admin APIs. So, unless allowPrivate is set:
//
//   - every connection's actual destination IP is checked at dial time
//     (after DNS resolution, so a name that resolves -- or re-resolves --
//     to an internal address is caught too), and anything that isn't a
//     public unicast address is refused;
//   - redirects are never followed, so a public URL can't bounce the
//     request inward;
//   - no HTTP proxy from the environment is used, since the dial-time
//     check would then only see the proxy's address.
func newWebhookClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{TLSHandshakeTimeout: timeout}
	if allowPrivate {
		transport.Proxy = http.ProxyFromEnvironment
	} else {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			return checkWebhookDestination(address)
		}
	}
	transport.DialContext = dialer.DialContext
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var errNonPublicDestination = errors.New("webhook destination is not a public address")

// cgnat is RFC 6598 shared address space, which netip doesn't classify
// as private but is just as internal in practice.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// checkWebhookDestination refuses a dial to anything but a public
// unicast address. address is "ip:port" as handed to a net.Dialer's
// Control hook, i.e. already resolved.
func checkWebhookDestination(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		cgnat.Contains(ip) || (ip.Is4() && ip.As4()[0] == 0) {
		return fmt.Errorf("%w: %s", errNonPublicDestination, ip)
	}
	return nil
}
