// Command sazu-watchd is SAZU's §11.4 delegation-change monitor: a
// standalone daemon, deliberately outside CoreDNS itself, that
// periodically re-checks every onboarded zone's chain of trust (the same
// "does a DS matching this zone's pinned key exist at the parent" check
// first contact and a §8.2 key rollover already perform), that its
// registered ZSKs are still served, and how soon its earliest RRSIG
// expires, and alerts the zone's registered §11.4 contact when any of
// those needs attention.
//
// Kept out of CoreDNS on purpose: this is a periodic background job, not
// request-driven, and its own failure mode (a slow or flaky query to some
// TLD server) must never be able to add latency to actual DNS answers, or
// tie monitoring continuity to the query-serving process's uptime. It
// reads the exact same SQLite database file CoreDNS's sazu plugin writes
// to (via -db), never anything of its own.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/sazu"
)

func main() {
	dbPath := flag.String("db", "", "path to the SQLite database CoreDNS's sazu plugin is using (required)")
	interval := flag.Duration("interval", 5*time.Minute, "how often to re-check every onboarded zone's chain of trust")
	once := flag.Bool("once", false, "run a single check pass and exit, instead of looping forever")
	smtpAddr := flag.String("smtp-addr", "", "SMTP server host:port for mailto: contact alerts (omit to disable email alerts)")
	smtpFrom := flag.String("smtp-from", "", "From address for email alerts")
	smtpUsername := flag.String("smtp-username", "", "SMTP auth username (omit for no auth)")
	smtpPasswordFile := flag.String("smtp-password-file", "", "path to a file containing the SMTP auth password")
	webhookTimeout := flag.Duration("webhook-timeout", 10*time.Second, "timeout for a single webhook POST")
	webhookAllowPrivate := flag.Bool("webhook-allow-private", false,
		"allow webhook alerts to loopback/private/link-local addresses and follow an HTTP proxy from the environment. "+
			"Webhook URLs are chosen by zone owners, so only enable this where every zone owner is trusted")
	flag.DurationVar(&expiryWarning, "expiry-warning", expiryWarning,
		"warn a zone's contact once its earliest RRSIG expires within this long")
	trustAnchorPath := flag.String("trust-anchor", "",
		"file of root DS/DNSKEY trust anchors (e.g. unbound-anchor's root.key); default: the built-in anchors")
	flag.Parse()

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: sazu-watchd -db <path> [-interval 5m] [-once] [-expiry-warning 168h] [-trust-anchor <path>] "+
			"[-smtp-addr host:port -smtp-from you@example.org [-smtp-username u -smtp-password-file p]] [-webhook-timeout 10s]")
		os.Exit(1)
	}

	var smtpPassword string
	if *smtpPasswordFile != "" {
		data, err := os.ReadFile(*smtpPasswordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sazu-watchd: reading -smtp-password-file: %v\n", err)
			os.Exit(1)
		}
		smtpPassword = strings.TrimRight(string(data), "\r\n")
	}

	db, err := sazu.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sazu-watchd: opening %s: %v\n", *dbPath, err)
		os.Exit(1)
	}
	defer db.Close()

	validator := sazu.NewValidator()
	if *trustAnchorPath != "" {
		anchors, err := sazu.LoadTrustAnchors(*trustAnchorPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sazu-watchd: -trust-anchor: %v\n", err)
			os.Exit(1)
		}
		validator.Anchors = anchors
	}
	dnskeys := liveDNSKEYFetcher{Timeout: 5 * time.Second}
	notifier := &Notifier{
		SMTPAddr:     *smtpAddr,
		SMTPFrom:     *smtpFrom,
		SMTPUsername: *smtpUsername,
		SMTPPassword: smtpPassword,
		HTTPClient:   newWebhookClient(*webhookTimeout, *webhookAllowPrivate),
	}
	state := make(map[string]*zoneState)

	for {
		runOnce(db, validator, dnskeys, notifier, state)
		if *once {
			return
		}
		time.Sleep(*interval)
	}
}

// runOnce performs one checkOnce pass and dispatches whatever alerts it
// returns, logging along the way -- separated from checkOnce itself so
// the state-transition decision logic stays unit-testable without any
// real network or SMTP/HTTP I/O (see watch_test.go).
func runOnce(db *sazu.DB, validator sazu.ChainValidator, dnskeys DNSKEYFetcher, notifier *Notifier, state map[string]*zoneState) {
	alerts, err := checkOnce(db, validator, dnskeys, state)
	if err != nil {
		log.Printf("sazu-watchd: check pass failed: %v", err)
		return
	}
	for _, alert := range alerts {
		switch alert.Kind {
		case AlertRolloverPending:
			if alert.Recovered {
				log.Printf("sazu-watchd: %s: KSK rollover no longer pending", alert.Zone)
			} else {
				log.Printf("sazu-watchd: %s: KSK rollover to key tag %d requested without the current KSK's co-signature", alert.Zone, alert.KeyTag)
			}
		case AlertSignatureExpiry:
			if alert.Recovered {
				log.Printf("sazu-watchd: %s: signatures refreshed", alert.Zone)
			} else {
				log.Printf("sazu-watchd: %s: earliest RRSIG expires %s", alert.Zone, alert.Expires.UTC().Format(time.RFC3339))
			}
		case AlertZSKMissing:
			if alert.Recovered {
				log.Printf("sazu-watchd: %s: ZSK key tag %d is being served again", alert.Zone, alert.KeyTag)
			} else {
				log.Printf("sazu-watchd: %s: registered ZSK key tag %d is missing from the served DNSKEY RRset", alert.Zone, alert.KeyTag)
			}
		default:
			if alert.Recovered {
				log.Printf("sazu-watchd: %s: chain-of-trust check recovered", alert.Zone)
			} else {
				log.Printf("sazu-watchd: %s: chain-of-trust check failed: %v", alert.Zone, alert.Err)
			}
		}
		if len(alert.Addresses) == 0 {
			log.Printf("sazu-watchd: %s: no contact registered, nothing to notify (see `sazuctl contact`)", alert.Zone)
			continue
		}
		for _, sendErr := range notifier.Send(alert) {
			log.Printf("sazu-watchd: %s: notifying: %v", alert.Zone, sendErr)
		}
	}
}
