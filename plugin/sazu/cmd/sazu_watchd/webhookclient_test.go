package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckWebhookDestination(t *testing.T) {
	refused := []string{
		"127.0.0.1:80", "[::1]:443", "10.1.2.3:80", "172.16.0.1:80", "192.168.1.1:80",
		"169.254.169.254:80", "[fe80::1]:80", "100.64.0.1:80", "0.0.0.0:80", "[fd00::1]:80",
		"[::ffff:127.0.0.1]:80", "224.0.0.1:80",
	}
	for _, addr := range refused {
		if err := checkWebhookDestination(addr); !errors.Is(err, errNonPublicDestination) {
			t.Errorf("%s: expected refusal, got %v", addr, err)
		}
	}
	for _, addr := range []string{"93.184.216.34:443", "[2606:4700::1111]:443"} {
		if err := checkWebhookDestination(addr); err != nil {
			t.Errorf("%s: expected a public address to be allowed, got %v", addr, err)
		}
	}
}

// TestWebhookClientRefusesLoopback: a zone owner registering a webhook
// on the monitoring host itself gets nothing sent there.
func TestWebhookClientRefusesLoopback(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer srv.Close()

	n := &Notifier{HTTPClient: trusting(newWebhookClient(2*time.Second, false))}
	if errs := n.Send(Alert{Zone: "example.org.", Addresses: []string{srv.URL}}); len(errs) == 0 {
		t.Fatalf("expected the loopback webhook to be refused")
	}
	if hit.Load() {
		t.Fatalf("the request reached the loopback server")
	}

	n = &Notifier{HTTPClient: trusting(newWebhookClient(2*time.Second, true))}
	if errs := n.Send(Alert{Zone: "example.org.", Addresses: []string{srv.URL}}); len(errs) != 0 || !hit.Load() {
		t.Fatalf("expected -webhook-allow-private to permit it, errs=%v hit=%v", errs, hit.Load())
	}
}

// TestWebhookClientDoesNotFollowRedirects: a public URL can't bounce the
// POST somewhere else.
func TestWebhookClientDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	n := &Notifier{HTTPClient: trusting(newWebhookClient(2*time.Second, true))}
	if errs := n.Send(Alert{Zone: "example.org.", Addresses: []string{redirector.URL}}); len(errs) == 0 {
		t.Fatalf("expected a redirect response to count as a failed delivery")
	}
	if followed.Load() {
		t.Fatalf("the redirect was followed")
	}
}

// trusting makes c accept the httptest TLS servers' certificate, keeping
// everything else about the webhook client as built.
func trusting(c *http.Client) *http.Client {
	tlsSrv := httptest.NewTLSServer(http.NotFoundHandler())
	defer tlsSrv.Close()
	c.Transport.(*http.Transport).TLSClientConfig = tlsSrv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return c
}
