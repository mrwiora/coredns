package sazu

import (
	"context"
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
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
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

// TestUpdatePrescan: RFC 2136 §3.2.1 and §3.4.1.3 -- an update naming a
// record outside the zone is NOTZONE, a prerequisite with a nonzero TTL
// or a delete with RDATA where none is allowed is FORMERR.
func TestUpdatePrescan(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)

	cases := []struct {
		name  string
		build func(m *dns.Msg)
		rcode int
	}{
		{"out-of-zone update", func(m *dns.Msg) {
			m.Insert([]dns.RR{testA("www.example.net.", net.IPv4(192, 0, 2, 1))})
		}, dns.RcodeNotZone},
		{"out-of-zone prerequisite", func(m *dns.Msg) {
			m.NameUsed([]dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: "example.net."}}})
			m.Insert([]dns.RR{testA("www.example.org.", net.IPv4(192, 0, 2, 1))})
		}, dns.RcodeNotZone},
		{"prerequisite with a TTL", func(m *dns.Msg) {
			m.Answer = append(m.Answer, &dns.ANY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeANY, Class: dns.ClassANY, Ttl: 60}})
			m.Insert([]dns.RR{testA("www.example.org.", net.IPv4(192, 0, 2, 1))})
		}, dns.RcodeFormatError},
		{"meta-type add", func(m *dns.Msg) {
			m.Ns = append(m.Ns, &dns.ANY{Hdr: dns.RR_Header{Name: "www.example.org.", Rrtype: dns.TypeANY, Class: dns.ClassINET, Ttl: 60}})
		}, dns.RcodeFormatError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetUpdate("example.org.")
			tc.build(m)
			if resp := sendRaw(t, addr, signNow(t, m, ksk, kskPriv)); resp.Rcode != tc.rcode {
				t.Fatalf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tc.rcode])
			}
		})
	}
}

// TestUpdateForZoneOutOfScopeIsNotAuth: RFC 2136 §3.1.1 -- a server not
// authoritative for the zone named answers NOTAUTH.
func TestUpdateForZoneOutOfScopeIsNotAuth(t *testing.T) {
	s := newTestSazu("example.org.")
	s.Next = nil
	m := new(dns.Msg)
	m.SetUpdate("example.net.")
	rcode, err := s.ServeDNS(context.Background(), &recordingResponseWriter{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}}, m)
	if err != nil || rcode != dns.RcodeNotAuth {
		t.Fatalf("rcode = %s (%v), want NOTAUTH", dns.RcodeToString[rcode], err)
	}
}
