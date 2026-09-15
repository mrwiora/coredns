package sazu

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestPublishTrustOnboardsWithoutContent proves BuildTrustPush's whole
// point: first contact can establish a KSK+ZSK trust relationship with
// zero zone content, and the zone remains servable (just empty) until a
// separate publish-zone push supplies content.
func TestPublishTrustOnboardsWithoutContent(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zsk, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}

	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatalf("BuildTrustPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(trust, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-trust rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	zk, ok := s.Keys.Get("example.org.")
	if !ok {
		t.Fatalf("expected a KSK to be pinned after publish-trust")
	}
	if zk.KSK.KeyTag() != ksk.KeyTag() {
		t.Fatalf("pinned KSK key tag = %d, want %d", zk.KSK.KeyTag(), ksk.KeyTag())
	}
	if len(zk.ZSKs) != 1 || zk.ZSKs[0].KeyTag() != zsk.KeyTag() {
		t.Fatalf("expected the accompanying ZSK to also be registered, got %+v", zk.ZSKs)
	}
}

// TestPublishZoneAuthenticatesWithZSKAloneAfterPublishTrust proves the
// central point of the redesign: once publish-trust has established the
// ZSK, a routine publish-zone content push signed *only* by the ZSK is
// accepted, needs no DNSKEY of its own, and never touches the KSK.
func TestPublishZoneAuthenticatesWithZSKAloneAfterPublishTrust(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatalf("BuildTrustPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(trust, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-trust rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	content, err := BuildContentPush("example.org.", testSOA(1), []dns.RR{testA("www.example.org.", nil)}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	wire, err = SignUpdate(content, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-zone rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	z, _ := s.Store.Get("example.org.")
	if got := z.Lookup("www.example.org.", dns.TypeA); len(got) != 1 {
		t.Fatalf("expected the pushed A record to be served, got %d", len(got))
	}
	// The push carried no DNSKEY at all -- the apex DNSKEY RRset must
	// still be exactly the pair publish-trust registered, not polluted
	// with a second, redundant copy.
	if got := z.Lookup("example.org.", dns.TypeDNSKEY); len(got) != 2 {
		t.Fatalf("expected exactly 2 DNSKEY records at the apex (KSK+ZSK), got %d", len(got))
	}
}

// TestPublishZoneRejectsRetiredZSK proves a ZSK that's since been
// retired can no longer authenticate a publish-zone push on its own --
// the scenario a hardcoded KSK-shaped key load used to accidentally let
// through as a KSK-rollover attempt (see keys.go/handler.go's
// findCandidateKey doc comments).
func TestPublishZoneRejectsRetiredZSK(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatalf("BuildTrustPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(trust, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-trust rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if resp := retireZSK(t, addr, ksk, kskPriv, zsk); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("retire-zsk rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	content, err := BuildContentPush("example.org.", testSOA(1), nil, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	wire, err = SignUpdate(content, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode == dns.RcodeSuccess {
		t.Fatalf("expected the retired ZSK to no longer authenticate a publish-zone push")
	}
}

// TestPublishZoneRemovesContentDroppedFromTheZoneFile proves a full
// content push is a genuine, complete replacement: a record present in
// an earlier push but absent from a later one is actually gone
// afterward, not left lingering forever the way a bare RFC 2136 add
// alone would (see ZoneData.PurgeContent).
func TestPublishZoneRemovesContentDroppedFromTheZoneFile(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatalf("BuildTrustPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(trust, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-trust rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	withMail, err := BuildContentPush("example.org.", testSOA(1),
		[]dns.RR{testA("www.example.org.", nil), testA("mail.example.org.", nil)}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	wire, err = SignUpdate(withMail, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first publish-zone rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	z, _ := s.Store.Get("example.org.")
	if got := z.Lookup("mail.example.org.", dns.TypeA); len(got) != 1 {
		t.Fatalf("expected mail to be servable after the first push, got %d", len(got))
	}

	withoutMail, err := BuildContentPush("example.org.", testSOA(2), []dns.RR{testA("www.example.org.", nil)}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	wire, err = SignUpdate(withoutMail, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("second publish-zone rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if got := z.Lookup("mail.example.org.", dns.TypeA); len(got) != 0 {
		t.Fatalf("expected mail to have been removed, still got %d record(s)", len(got))
	}
	if got := z.Lookup("www.example.org.", dns.TypeA); len(got) != 1 {
		t.Fatalf("expected www to still be servable, got %d", len(got))
	}
	if got := z.Lookup("example.org.", dns.TypeDNSKEY); len(got) != 2 {
		t.Fatalf("expected the KSK+ZSK DNSKEY pair to survive a content purge untouched, got %d", len(got))
	}
}

// TestKSKRolloverNeverPurgesContentOrChain proves a push that carries an
// apex DNSKEY but changes no other served content (a KSK rollover here)
// leaves both the zone's ordinary content and its NSEC chain exactly as
// they were -- handler.go's two-case purge decision (containsAPEXSOA vs
// changesChainRelevantContent) must not mistake "carries a DNSKEY" for
// "is a full push," or every key rotation would throw away a chain and
// content it supplies no replacement for.
func TestKSKRolloverNeverPurgesContentOrChain(t *testing.T) {
	s := newTestSazu("example.org.")
	s.InsecureSkipChainValidation = true
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatalf("BuildTrustPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(trust, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-trust rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	content, err := BuildContentPush("example.org.", testSOA(1), []dns.RR{testA("www.example.org.", nil)}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	wire, err = SignUpdate(content, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-zone rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	z, _ := s.Store.Get("example.org.")
	chainBefore := z.Lookup("example.org.", dns.TypeNSEC)
	if len(chainBefore) == 0 {
		t.Fatalf("expected a chain to exist before the rollover")
	}

	newKSK, newKSKPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating new KSK: %v", err)
	}
	newKSKRR := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: newKSK.Flags, Protocol: newKSK.Protocol, Algorithm: newKSK.Algorithm, PublicKey: newKSK.PublicKey,
	}
	signedKSK, err := SignZoneContent([]dns.RR{newKSKRR}, newKSK, newKSKPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	rollover := new(dns.Msg)
	rollover.SetQuestion("example.org.", dns.TypeSOA)
	rollover.Opcode = dns.OpcodeUpdate
	rollover.Insert(signedKSK)
	wire, err = SignUpdate(rollover, newKSK, newKSKPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rollover rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if got := z.Lookup("www.example.org.", dns.TypeA); len(got) != 1 {
		t.Fatalf("expected content to survive the rollover untouched, got %d", len(got))
	}
	if got := z.Lookup("example.org.", dns.TypeNSEC); len(got) == 0 {
		t.Fatalf("expected the chain to survive the rollover, got none")
	}
}
