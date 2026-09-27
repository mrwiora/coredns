package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Notifier sends one Alert to each of its registered contact addresses,
// dispatching on scheme: "mailto:" via SMTP, "http://"/"https://" via a
// webhook POST -- both alerting mechanisms §11's design left "TBD"
// between, kept both rather than picking one so a zone's registered
// contact (sazuctl contact -address ...) decides per-address which
// channel(s) it wants, with no separate per-zone daemon configuration.
type Notifier struct {
	SMTPAddr     string // host:port, e.g. "smtp.example.org:587"; empty disables email entirely
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string
	HTTPClient   *http.Client
}

// Send dispatches alert to every one of its addresses, returning one
// error per address that failed (nil slice if all succeeded, or if there
// were no addresses to notify at all).
func (n *Notifier) Send(alert Alert) []error {
	var errs []error
	for _, addr := range alert.Addresses {
		var err error
		switch {
		case strings.HasPrefix(addr, "mailto:"):
			err = n.sendEmail(strings.TrimPrefix(addr, "mailto:"), alert)
		case strings.HasPrefix(addr, "http://"), strings.HasPrefix(addr, "https://"):
			err = n.sendWebhook(addr, alert)
		default:
			// contact.go's validateContactAddresses already restricts
			// stored addresses to these schemes -- reaching here would
			// mean the persisted data itself is corrupt, not a normal
			// runtime condition.
			err = fmt.Errorf("address %q has no recognized scheme", addr)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", addr, err))
		}
	}
	return errs
}

// webhookPayload is the JSON body a webhook alert POSTs. Deliberately
// small and self-describing rather than any existing schema -- there is
// no established standard for "DNS delegation changed" webhooks to
// interoperate with, so this just carries what a receiver needs to
// react.
type webhookPayload struct {
	Zone      string `json:"zone"`
	Kind      string `json:"kind"`
	Recovered bool   `json:"recovered"`
	Error     string `json:"error,omitempty"`
	KeyTag    uint16 `json:"key_tag,omitempty"`
	Expires   string `json:"expires,omitempty"`
	At        string `json:"at"`
}

func alertKindName(k AlertKind) string {
	switch k {
	case AlertZSKMissing:
		return "zsk_missing"
	case AlertSignatureExpiry:
		return "signature_expiry"
	}
	return "chain_of_trust"
}

func (n *Notifier) sendWebhook(url string, alert Alert) error {
	payload := webhookPayload{
		Zone:      alert.Zone,
		Kind:      alertKindName(alert.Kind),
		Recovered: alert.Recovered,
		KeyTag:    alert.KeyTag,
		At:        time.Now().UTC().Format(time.RFC3339),
	}
	if alert.Err != nil {
		payload.Error = alert.Err.Error()
	}
	if !alert.Expires.IsZero() {
		payload.Expires = alert.Expires.UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := n.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}

func (n *Notifier) sendEmail(to string, alert Alert) error {
	if n.SMTPAddr == "" {
		return fmt.Errorf("no -smtp-addr configured, cannot send email alerts")
	}
	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	var subject, body string
	body = fmt.Sprintf("Zone: %s\n", alert.Zone)
	switch alert.Kind {
	case AlertSignatureExpiry:
		if alert.Recovered {
			subject = fmt.Sprintf("SAZU: %s signatures refreshed", alert.Zone)
			body += "The zone's earliest RRSIG expiration is outside the warning window again.\n"
		} else {
			subject = fmt.Sprintf("SAZU: %s signatures expire %s", alert.Zone, alert.Expires.UTC().Format("2006-01-02 15:04 MST"))
			body += fmt.Sprintf("The zone's earliest RRSIG expires at %s.\n"+
				"This server never re-signs anything: unless a fresh publish-zone push arrives before then,\n"+
				"validating resolvers will start treating the zone as bogus (SERVFAIL).\n",
				alert.Expires.UTC().Format(time.RFC3339))
		}
	case AlertZSKMissing:
		if alert.Recovered {
			subject = fmt.Sprintf("SAZU: %s ZSK key tag %d is being served again", alert.Zone, alert.KeyTag)
			body += fmt.Sprintf("ZSK key tag %d is present in the served DNSKEY RRset again.\n", alert.KeyTag)
		} else {
			subject = fmt.Sprintf("SAZU: %s is missing a registered ZSK", alert.Zone)
			body += fmt.Sprintf("Registered ZSK key tag %d is missing from the zone's served DNSKEY RRset.\n"+
				"Routine pushes authenticated by this key will be rejected until it's restored\n"+
				"or replaced (sazuctl add-zsk / retire-zsk).\n", alert.KeyTag)
		}
	default:
		if alert.Recovered {
			subject = fmt.Sprintf("SAZU: %s delegation check recovered", alert.Zone)
			body += "Chain-of-trust validation is passing again.\n"
		} else {
			subject = fmt.Sprintf("SAZU: delegation change detected for %s", alert.Zone)
			body += fmt.Sprintf("Chain-of-trust validation failed: %v\n", alert.Err)
		}
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", n.SMTPFrom, to, subject, body)

	host, _, err := net.SplitHostPort(n.SMTPAddr)
	if err != nil {
		return fmt.Errorf("-smtp-addr must be host:port: %w", err)
	}
	var auth smtp.Auth
	if n.SMTPUsername != "" {
		auth = smtp.PlainAuth("", n.SMTPUsername, n.SMTPPassword, host)
	}
	return smtp.SendMail(n.SMTPAddr, auth, n.SMTPFrom, []string{to}, []byte(msg))
}
