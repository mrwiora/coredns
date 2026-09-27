package sazu

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestSIG0SignerNameMustBeTheZoneApex: a SIG(0) made with the zone's key
// but naming another signer is refused.
func TestSIG0SignerNameMustBeTheZoneApex(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)
	op, err := BuildContactOp("example.org.", []string{"mailto:ops@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Insert([]dns.RR{op})
	other := *ksk
	other.Hdr.Name = "someone-else.example."
	now := time.Now()
	wire, err := SignUpdate(m, &other, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeNotAuth {
		t.Fatalf("rcode = %s, want NOTAUTH", dns.RcodeToString[resp.Rcode])
	}
}

// TestZoneSectionMustBeSOA: RFC 2136's zone section names the zone with
// type SOA; anything else is refused.
func TestZoneSectionMustBeSOA(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)
	op, err := BuildContactOp("example.org.", []string{"mailto:ops@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.Opcode = dns.OpcodeUpdate
	m.Insert([]dns.RR{op})
	if resp := sendRaw(t, addr, signNow(t, m, ksk, kskPriv)); resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}

// TestEmptyUpdateIsRefused: an update that does nothing matches no
// message kind.
func TestEmptyUpdateIsRefused(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	if resp := sendRaw(t, addr, signNow(t, m, ksk, kskPriv)); resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}

// TestContentPushMayNotDelete: a complete zone has nothing to delete.
func TestContentPushMayNotDelete(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)
	m, err := BuildContentPush("example.org.", testSOA(5), []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.RemoveRRset([]dns.RR{testA("old.example.org.", nil)})
	if resp := sendRaw(t, addr, signNow(t, m, zsk, zskPriv)); resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}

// TestWebhookContactMustBeHTTPS: plain-http webhooks are refused.
func TestWebhookContactMustBeHTTPS(t *testing.T) {
	if _, err := BuildContactOp("example.org.", []string{"http://hooks.example.org/sazu"}); err == nil {
		t.Fatalf("expected an http:// webhook to be refused")
	}
	if _, err := BuildContactOp("example.org.", []string{"https://hooks.example.org/sazu", "mailto:ops@example.org"}); err != nil {
		t.Fatalf("expected https:// and mailto: to be accepted: %v", err)
	}
}
