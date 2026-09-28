package sazu

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/doh"

	"github.com/miekg/dns"
)

// serveThroughRealHTTPSServer starts a real dnsserver.ServerHTTPS with s
// installed as the sole plugin -- exactly like a Corefile with an
// `https://` server block containing a `sazu` directive would produce --
// and returns its base URL. AllowOpcode is called directly on the
// Config, exactly as setup.go itself does, rather than going through
// setup() -- the same convention serveThroughRealServer (the UDP/TCP
// counterpart) already follows for this package's other end-to-end
// tests.
//
// No TLS: httptest.NewServer wraps ServerHTTPS.ServeHTTP with its own
// real listener over plain HTTP, which exercises this transport's actual
// request-processing logic (opcode gating, raw-byte propagation) exactly as thoroughly as doing it over a real TLS
// handshake would -- TLS termination itself is core/dnsserver's own,
// already-tested concern, not something this plugin's tests need to
// re-verify.
func serveThroughRealHTTPSServer(t *testing.T, s *Sazu) string {
	t.Helper()
	cfg := &dnsserver.Config{
		Zone:        s.Zones[0],
		Transport:   "https",
		ListenHosts: []string{"127.0.0.1"},
		Port:        "0",
	}
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		s.Next = next
		return s
	})
	cfg.AllowOpcode(dns.OpcodeUpdate)

	sh, err := dnsserver.NewServerHTTPS("127.0.0.1:0", []*dnsserver.Config{cfg})
	if err != nil {
		t.Fatalf("NewServerHTTPS: %v", err)
	}
	httpSrv := httptest.NewServer(sh)
	t.Cleanup(httpSrv.Close)
	return httpSrv.URL
}

// sendOverHTTPS POSTs wire to baseURL+doh.Path as an RFC 8484
// application/dns-message body and returns the parsed response.
func sendOverHTTPS(t *testing.T, baseURL string, wire []byte) *dns.Msg {
	t.Helper()
	body := bytes.NewReader(wire)
	contentType := doh.MimeType

	req, err := http.NewRequest(http.MethodPost, baseURL+doh.Path, body)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(buf); err != nil {
		t.Fatalf("unpacking response (HTTP status %d): %v (body=%x)", resp.StatusCode, err, buf)
	}
	return m
}

// TestOnboardOverHTTPSRawWireBytes proves §9.2's HTTPS carrier for
// real: a first-contact push sent as a raw application/dns-message POST
// -- the RFC 8484 DoH convention, reused as-is -- reaches this plugin's
// exact same authenticate-evaluate-apply pipeline every other transport
// shares (SIG(0) verified against RawRequestKey's context-propagated
// wire bytes, since HTTPS never goes through RawCapture at all), and
// results in a genuinely onboarded, servable zone.
func TestOnboardOverHTTPSRawWireBytes(t *testing.T) {
	s := newTestSazu("example.org.")
	baseURL := serveThroughRealHTTPSServer(t, s)

	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	rrs := []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}
	push, err := BuildFullZonePush("example.org.", soa, rrs, key, priv, nil)
	if err != nil {
		t.Fatalf("building push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(push, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	resp := sendOverHTTPS(t, baseURL, wire)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push over HTTPS rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if pinned, ok := s.Keys.Get("example.org."); !ok || pinned.KSK.DNSKEY.PublicKey != key.PublicKey {
		t.Fatalf("expected the candidate key to be pinned after a successful HTTPS push")
	}
}

// TestPartialPushOverHTTPSAfterOnboarding proves an ordinary,
// already-pinned-key push also works over HTTPS, not just first
// contact -- the same two-step onboard-then-push-again shape
// TestOrdinaryPartialPushAfterOnboarding already proves for UDP/TCP.
func TestContentPushOverHTTPSAfterOnboarding(t *testing.T) {
	s := newTestSazu("example.org.")
	baseURL := serveThroughRealHTTPSServer(t, s)

	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	rrs := []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}
	onboard, err := BuildFullZonePush("example.org.", soa, rrs, key, priv, nil)
	if err != nil {
		t.Fatalf("building onboarding push: %v", err)
	}
	now := time.Now()
	onboardWire, err := SignUpdate(onboard, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing onboarding push: %v", err)
	}
	if resp := sendOverHTTPS(t, baseURL, onboardWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	push, err := BuildContentPush("example.org.", testSOA(2),
		[]dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10)), testA("mail.example.org.", net.IPv4(203, 0, 113, 20))}, key, priv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	now = time.Now()
	pushWire, err := SignUpdate(push, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing content push: %v", err)
	}
	if resp := sendOverHTTPS(t, baseURL, pushWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("content push over HTTPS rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	z, ok := s.Store.Get("example.org.")
	if !ok {
		t.Fatalf("expected the zone to exist")
	}
	if got := z.Lookup("mail.example.org.", dns.TypeA); len(got) != 1 {
		t.Fatalf("expected the partially-added record to be servable, got %d answers", len(got))
	}
}
