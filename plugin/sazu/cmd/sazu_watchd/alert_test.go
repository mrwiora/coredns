package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotifierSendWebhookPostsExpectedPayload(t *testing.T) {
	var got webhookPayload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json, got %q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decoding webhook body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{HTTPClient: srv.Client()}
	alert := Alert{Zone: "example.org.", Addresses: []string{srv.URL}, Err: fmt.Errorf("no DS published")}
	if errs := n.Send(alert); len(errs) != 0 {
		t.Fatalf("expected no errors, got %+v", errs)
	}
	if got.Zone != "example.org." || got.Recovered || got.Error != "no DS published" {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestNotifierSendWebhookReportsNonOKStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := &Notifier{HTTPClient: srv.Client()}
	alert := Alert{Zone: "example.org.", Addresses: []string{srv.URL}}
	errs := n.Send(alert)
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error for a 500 response, got %+v", errs)
	}
}

func TestNotifierSendRecoveryPayloadCarriesNoError(t *testing.T) {
	var got webhookPayload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{HTTPClient: srv.Client()}
	alert := Alert{Zone: "example.org.", Addresses: []string{srv.URL}, Recovered: true}
	if errs := n.Send(alert); len(errs) != 0 {
		t.Fatalf("expected no errors, got %+v", errs)
	}
	if !got.Recovered || got.Error != "" {
		t.Fatalf("expected a recovery payload with no error field, got %+v", got)
	}
}

func TestNotifierSendWebhookZSKMissingPayloadCarriesKind(t *testing.T) {
	var got webhookPayload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{HTTPClient: srv.Client()}
	alert := Alert{Zone: "example.org.", Addresses: []string{srv.URL}, Kind: AlertZSKMissing, KeyTag: 12345}
	if errs := n.Send(alert); len(errs) != 0 {
		t.Fatalf("expected no errors, got %+v", errs)
	}
	if got.Kind != "zsk_missing" || got.KeyTag != 12345 || got.Recovered {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestNotifierSendWebhookChainOfTrustPayloadCarriesKind(t *testing.T) {
	var got webhookPayload
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{HTTPClient: srv.Client()}
	alert := Alert{Zone: "example.org.", Addresses: []string{srv.URL}, Err: fmt.Errorf("no DS published")}
	if errs := n.Send(alert); len(errs) != 0 {
		t.Fatalf("expected no errors, got %+v", errs)
	}
	if got.Kind != "chain_of_trust" {
		t.Fatalf("expected the zero-value Kind to render as chain_of_trust, got %+v", got)
	}
}

func TestNotifierSendEmailWithoutSMTPAddrConfiguredFails(t *testing.T) {
	n := &Notifier{} // no SMTPAddr
	alert := Alert{Zone: "example.org.", Addresses: []string{"mailto:ops@example.org"}, Err: fmt.Errorf("broken")}
	errs := n.Send(alert)
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error when SMTP isn't configured, got %+v", errs)
	}
}

func TestNotifierSendEmailRejectsInvalidAddress(t *testing.T) {
	n := &Notifier{SMTPAddr: "smtp.example.org:587", SMTPFrom: "alerts@example.org"}
	alert := Alert{Zone: "example.org.", Addresses: []string{"mailto:not-an-email"}, Err: fmt.Errorf("broken")}
	errs := n.Send(alert)
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error for an invalid email address, got %+v", errs)
	}
}

func TestNotifierSendUnknownSchemeReportsError(t *testing.T) {
	n := &Notifier{}
	alert := Alert{Zone: "example.org.", Addresses: []string{"ftp://example.org"}}
	errs := n.Send(alert)
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error for an unrecognized scheme, got %+v", errs)
	}
}

func TestNotifierSendDispatchesToMultipleAddressesIndependently(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := &Notifier{HTTPClient: srv.Client()} // email will fail (no SMTP configured), webhook should still succeed
	alert := Alert{Zone: "example.org.", Addresses: []string{"mailto:ops@example.org", srv.URL}, Err: fmt.Errorf("broken")}
	errs := n.Send(alert)
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error (the email address, since no SMTP is configured), got %+v", errs)
	}
}

// TestNotifierSendsWebhooksOnlyOverHTTPS: an http:// address is not a
// webhook destination; nothing is sent to it.
func TestNotifierSendsWebhooksOnlyOverHTTPS(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer srv.Close()
	n := &Notifier{HTTPClient: srv.Client()}
	if errs := n.Send(Alert{Zone: "example.org.", Addresses: []string{srv.URL}}); len(errs) != 1 {
		t.Fatalf("expected the http:// address to be refused, got %v", errs)
	}
	if hit.Load() {
		t.Fatalf("an http:// webhook was contacted")
	}
}

// TestComposeEmailIsRFC5322: the alert email carries the fields RFC 5322
// requires (Date, From) and recommends (Message-ID), a MIME plain-text
// body, CRLF line endings, and an RFC 2047-encoded non-ASCII subject.
func TestComposeEmailIsRFC5322(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	raw := composeEmail("alerts@example.org", "owner@example.org", "SAZU: zone bücher.example", "line one\nline two\n", now)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a parseable RFC 5322 message: %v", err)
	}
	if d, err := msg.Header.Date(); err != nil || !d.Equal(now) {
		t.Fatalf("Date = %v (%v), want %v", d, err, now)
	}
	if id := msg.Header.Get("Message-Id"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.org>") {
		t.Fatalf("Message-ID = %q", id)
	}
	dec := new(mime.WordDecoder)
	if subj, err := dec.DecodeHeader(msg.Header.Get("Subject")); err != nil || subj != "SAZU: zone bücher.example" {
		t.Fatalf("Subject = %q (%v)", subj, err)
	}
	if msg.Header.Get("Content-Type") != "text/plain; charset=utf-8" || msg.Header.Get("Mime-Version") != "1.0" {
		t.Fatalf("missing MIME headers: %v", msg.Header)
	}
	if strings.Contains(strings.ReplaceAll(string(raw), "\r\n", ""), "\n") {
		t.Fatalf("bare LF in message")
	}
}
