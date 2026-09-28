package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/doh"

	"github.com/miekg/dns"
)

// TestSendOverHTTPRoundTrips: sendOverHTTP is sazuctl's own client-side code for pushing over an https://
// target, distinct from plugin/sazu/https_test.go's coverage of the
// *server* side of this same wire protocol via a hand-built HTTP client.
// Runs against a real httptest.Server, exactly like that server-side test
// runs a real dnsserver.ServerHTTPS wrapped in one -- not a live network,
// but a real POST/response round trip through net/http.
func TestSendOverHTTPRoundTrips(t *testing.T) {
	defer func(c *http.Client) { httpsClient = c }(httpsClient)
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("packing update: %v", err)
	}

	cases := []struct {
		name    string
		rcode   int
		wantErr bool
	}{
		{"accepted", dns.RcodeSuccess, false},
		{"refused", dns.RcodeRefused, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != doh.Path {
					t.Errorf("request path = %s, want %s", r.URL.Path, doh.Path)
				}
				if ct := r.Header.Get("Content-Type"); ct != doh.MimeType {
					t.Errorf("request Content-Type = %s, want %s", ct, doh.MimeType)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("reading request body: %v", err)
				}
				req := new(dns.Msg)
				if err := req.Unpack(body); err != nil {
					t.Fatalf("unpacking request wire bytes: %v", err)
				}
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.Rcode = c.rcode
				respWire, err := resp.Pack()
				if err != nil {
					t.Fatalf("packing response: %v", err)
				}
				w.Header().Set("Content-Type", doh.MimeType)
				w.Write(respWire)
			}))
			defer ts.Close()

			// key is nil: interpretResponse only dereferences it for the
			// ERR_NO_DS_PUBLISHED/ERR_UNKNOWN_SIGNER diagnostic-guidance
			// branches, neither of which a bare RcodeRefused with no
			// status reaches.
			httpsClient = ts.Client()
			err := sendOverHTTP("example.org.", wire, nil, ts.URL)
			if c.wantErr && err == nil {
				t.Fatalf("expected an error for rcode %s, got nil", dns.RcodeToString[c.rcode])
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestPlainHTTPTargetIsRefused: DNS over HTTPS is HTTPS only (RFC 8484 §5).
func TestPlainHTTPTargetIsRefused(t *testing.T) {
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	err = signSelfVerifyAndSend("example.org.", wire, nil, "http://127.0.0.1:1", false)
	if err == nil || !strings.Contains(err.Error(), "RFC 8484") {
		t.Fatalf("expected an http:// target to be refused, got %v", err)
	}
}
