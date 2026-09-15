package sazu

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSplitDecommissionOpsFindsDirectiveAndStripsIt(t *testing.T) {
	zone := "example.org."
	op := BuildDecommissionOp(zone)
	rest, decommission, err := splitDecommissionOps(asAddOps(t, []dns.RR{op}), zone)
	if err != nil {
		t.Fatalf("splitDecommissionOps: %v", err)
	}
	if !decommission {
		t.Fatalf("expected the directive to be recognized")
	}
	if len(rest) != 0 {
		t.Fatalf("expected the directive to be stripped out, got %+v", rest)
	}
}

func TestSplitDecommissionOpsAbsentIsANoOp(t *testing.T) {
	rr := testA("www.example.org.", net.IPv4(203, 0, 113, 10))
	rest, decommission, err := splitDecommissionOps([]dns.RR{rr}, "example.org.")
	if err != nil {
		t.Fatalf("splitDecommissionOps: %v", err)
	}
	if decommission {
		t.Fatalf("expected no directive to be found")
	}
	if len(rest) != 1 {
		t.Fatalf("expected the ordinary op to survive untouched, got %+v", rest)
	}
}

func TestSplitDecommissionOpsRejectsMoreThanOne(t *testing.T) {
	op := BuildDecommissionOp("example.org.")
	_, _, err := splitDecommissionOps(asAddOps(t, []dns.RR{op, op}), "example.org.")
	if err == nil {
		t.Fatalf("expected an error for two decommission directives in one update")
	}
	if !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("expected a more-than-one-directive error, got %v", err)
	}
}

func TestSplitDecommissionOpsRejectsMixingWithOtherOps(t *testing.T) {
	op := BuildDecommissionOp("example.org.")
	rr := testA("www.example.org.", net.IPv4(203, 0, 113, 10))
	_, _, err := splitDecommissionOps(asAddOps(t, []dns.RR{op, rr}), "example.org.")
	if err == nil {
		t.Fatalf("expected an error for a decommission directive mixed with an ordinary op")
	}
	if !strings.Contains(err.Error(), "mixed") {
		t.Fatalf("expected a mixed-with-another-op error, got %v", err)
	}
}

func TestSplitDecommissionOpsDropsStrayRRSIG(t *testing.T) {
	op := BuildDecommissionOp("example.org.")
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: decommissionOwnerName("example.org."), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeTXT,
	}
	rest, decommission, err := splitDecommissionOps(asAddOps(t, []dns.RR{op, sig}), "example.org.")
	if err != nil {
		t.Fatalf("splitDecommissionOps: %v", err)
	}
	if !decommission {
		t.Fatalf("expected the directive to be recognized")
	}
	if len(rest) != 0 {
		t.Fatalf("expected the stray RRSIG to be dropped silently, got %+v", rest)
	}
}

// TestServeUpdateDecommissionRemovesEverything proves the full
// server-side effect: KSK, ZSK, content, and contact registration all
// gone from Store/KeyRegistry/Contacts, a subsequent query for the zone
// falls through as if it had never been onboarded, and re-onboarding
// from scratch afterward works (nothing left over to conflict with a
// fresh first contact).
func TestServeUpdateDecommissionRemovesEverything(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	onboardWithKSK(t, addr, ksk, kskPriv)

	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	if resp := addZSK(t, addr, ksk, kskPriv, zsk); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	_ = zskPriv

	contactMsg := new(dns.Msg)
	contactMsg.SetQuestion("example.org.", dns.TypeSOA)
	contactMsg.Opcode = dns.OpcodeUpdate
	op, err := BuildContactOp("example.org.", []string{"mailto:ops@example.org"})
	if err != nil {
		t.Fatalf("BuildContactOp: %v", err)
	}
	contactMsg.Insert([]dns.RR{op})
	now := time.Now()
	contactWire, err := SignUpdate(contactMsg, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing contact push: %v", err)
	}
	if resp := sendRaw(t, addr, contactWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("contact push rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	if _, ok := s.Keys.Get("example.org."); !ok {
		t.Fatalf("expected the zone's keys to exist before decommissioning")
	}
	if _, ok := s.Contacts.Get("example.org."); !ok {
		t.Fatalf("expected the zone's contact to exist before decommissioning")
	}

	decommMsg := BuildDecommissionPush("example.org.")
	now = time.Now()
	decommWire, err := SignUpdate(decommMsg, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing decommission push: %v", err)
	}
	if resp := sendRaw(t, addr, decommWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("decommission-zone rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if _, ok := s.Keys.Get("example.org."); ok {
		t.Fatalf("expected the zone's keys to be gone after decommissioning")
	}
	if _, ok := s.Store.Get("example.org."); ok {
		t.Fatalf("expected the zone's content to be gone after decommissioning")
	}
	if _, ok := s.Contacts.Get("example.org."); ok {
		t.Fatalf("expected the zone's contact to be gone after decommissioning")
	}

	// A query for the now-decommissioned zone must behave exactly like
	// one for a zone that was never onboarded at all.
	answer := query(t, addr, "www.example.org.", dns.TypeA)
	if len(answer.Answer) != 0 {
		t.Fatalf("expected no answer for a decommissioned zone, got %+v", answer.Answer)
	}

	// Re-onboarding from scratch afterward must work cleanly -- nothing
	// left over from before should conflict with a fresh first contact.
	newKSK, newKSKPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating fresh KSK: %v", err)
	}
	onboardWithKSK(t, addr, newKSK, newKSKPriv)
	if zk, ok := s.Keys.Get("example.org."); !ok || zk.KSK.KeyTag() != newKSK.KeyTag() {
		t.Fatalf("expected re-onboarding after decommission to succeed with the new KSK")
	}
}

// TestServeUpdateDecommissionRejectedWhenAuthenticatedByZSK proves
// decommissioning requires the zone's own KSK specifically -- an
// otherwise-valid, already-authorized ZSK must not be enough, the same
// tier of authorization first contact and a rollover already require.
func TestServeUpdateDecommissionRejectedWhenAuthenticatedByZSK(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	onboardWithKSK(t, addr, ksk, kskPriv)

	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	if resp := addZSK(t, addr, ksk, kskPriv, zsk); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	decommMsg := BuildDecommissionPush("example.org.")
	now := time.Now()
	decommWire, err := SignUpdate(decommMsg, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing decommission push: %v", err)
	}
	resp := sendRaw(t, addr, decommWire)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("decommission-zone (authenticated by ZSK) rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if status, ok := diagnosticStatus(resp); !ok || status != statusErrDecommissionRequiresKSK {
		t.Fatalf("expected %s diagnostic, got status=%q ok=%v", statusErrDecommissionRequiresKSK, status, ok)
	}

	// Confirm it's genuinely still intact -- rejected, not partially
	// applied.
	if _, ok := s.Keys.Get("example.org."); !ok {
		t.Fatalf("expected the zone's keys to still exist after a rejected decommission attempt")
	}
}

// TestServeUpdateDecommissionOfUnknownZoneIsRefused proves a decommission
// directive for a zone this server has never onboarded is refused rather
// than treated as a (vacuous) success -- there is no existing KSK to
// authenticate it with, so the same KSK-authentication requirement
// already refuses it, but worth its own test given how easy it would be
// to accidentally special-case "empty target" as "success."
func TestServeUpdateDecommissionOfUnknownZoneIsRefused(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	// A first-contact-shaped candidate key, self-signed, to attempt
	// decommissioning a zone that was never onboarded in the first
	// place.
	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	decommMsg := BuildDecommissionPush("example.org.")
	now := time.Now()
	decommWire, err := SignUpdate(decommMsg, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing decommission push: %v", err)
	}
	resp := sendRaw(t, addr, decommWire)
	if resp.Rcode == dns.RcodeSuccess {
		t.Fatalf("expected decommissioning a never-onboarded zone to be refused, not accepted")
	}
}
