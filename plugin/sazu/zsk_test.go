package sazu

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// onboardWithKSK sends a minimal first-contact push for "example.org."
// signed by ksk over a real socket, and fails the test unless it's
// accepted -- shared setup for every ZSK test below.
func onboardWithKSK(t *testing.T, addr string, ksk *dns.DNSKEY, kskPriv ed25519.PrivateKey) {
	t.Helper()
	onboard, err := BuildFullZonePush("example.org.", testSOA(1), nil, ksk, kskPriv, nil)
	if err != nil {
		t.Fatalf("building onboarding push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(onboard, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing onboarding push: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
}

// addZSK sends an ordinary, already-authenticated push (signed by
// authKey, the KSK or an already-authorized ZSK) that adds zsk's DNSKEY
// record at the zone apex -- the cheap registration path, with no chain-
// of-trust network walk, findNewZSKCandidate/AddZSK exist for. The
// DNSKEY insert itself is signed by authKey too (RFC 4034's convention:
// whichever key is already trusted signs the DNSKEY RRset), since
// content-signature verification is mandatory on every push, key
// management included.
func addZSK(t *testing.T, addr string, authKey *dns.DNSKEY, authPriv ed25519.PrivateKey, zsk *dns.DNSKEY) *dns.Msg {
	t.Helper()
	zskRR := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     zsk.Flags,
		Protocol:  zsk.Protocol,
		Algorithm: zsk.Algorithm,
		PublicKey: zsk.PublicKey,
	}
	now := time.Now()
	signed, err := SignZoneContent([]dns.RR{zskRR}, authKey, authPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("signing ZSK DNSKEY content: %v", err)
	}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate
	m.Insert(signed)
	wire, err := SignUpdate(m, authKey, authPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing ZSK-add push: %v", err)
	}
	return sendRaw(t, addr, wire)
}

// retireZSK sends an RFC 2136 §2.5.4 "delete one RR" push removing
// zsk's DNSKEY record, authenticated by authKey.
func retireZSK(t *testing.T, addr string, authKey *dns.DNSKEY, authPriv ed25519.PrivateKey, zsk *dns.DNSKEY) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate
	m.Remove([]dns.RR{&dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     zsk.Flags,
		Protocol:  zsk.Protocol,
		Algorithm: zsk.Algorithm,
		PublicKey: zsk.PublicKey,
	}})
	now := time.Now()
	wire, err := SignUpdate(m, authKey, authPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing ZSK-retire push: %v", err)
	}
	return sendRaw(t, addr, wire)
}

// TestZSKCanBeRegisteredOverAnOrdinaryPush proves the cheap registration
// path: a ZSK added via an ordinary, KSK-authenticated push is accepted
// with no chain-of-trust network walk (s.InsecureSkipChainValidation
// stays true throughout -- if this path incorrectly fell into the
// KSK-rollover branch instead, s.Validator would need to be consulted,
// which newTestSazu's default fakeValidator-less Validator would fail
// loudly on).
func TestZSKCanBeRegisteredOverAnOrdinaryPush(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	onboardWithKSK(t, addr, ksk, kskPriv)

	zsk, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	resp := addZSK(t, addr, ksk, kskPriv, zsk)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ZSK registration rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	zk, ok := s.Keys.Get("example.org.")
	if !ok {
		t.Fatalf("expected zone keys to exist")
	}
	if len(zk.ZSKs) != 1 || zk.ZSKs[0].DNSKEY.PublicKey != zsk.PublicKey {
		t.Fatalf("expected the new ZSK to be registered, got %+v", zk.ZSKs)
	}
	if zk.KSK.DNSKEY.PublicKey != ksk.PublicKey {
		t.Fatalf("expected the KSK to be unaffected by registering a ZSK")
	}
}

// TestRegisteringAZSKIsOptionalZoneBehaviorIsUnchangedWithoutOne proves
// the central design constraint: a zone that never registers a ZSK
// behaves exactly as SAZU always has -- an ordinary partial push signed
// by the KSK alone still works with no ZSK involved anywhere.
func TestRegisteringAZSKIsOptionalZoneBehaviorIsUnchangedWithoutOne(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	onboardWithKSK(t, addr, ksk, kskPriv)

	now := time.Now()
	signedA, err := SignZoneContent([]dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, ksk, kskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	partial := new(dns.Msg)
	partial.SetQuestion("example.org.", dns.TypeSOA)
	partial.Opcode = dns.OpcodeUpdate
	partial.Insert(signedA)
	wire, err := SignUpdate(partial, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	zk, _ := s.Keys.Get("example.org.")
	if len(zk.ZSKs) != 0 {
		t.Fatalf("expected zero ZSKs on a zone that never registered one, got %d", len(zk.ZSKs))
	}
}

// TestZSKAuthenticatesFurtherTransactionsOnceRegistered proves the
// practical point of the split: once registered, a ZSK's own SIG(0) can
// authenticate later pushes on its own, with no KSK involvement at all.
func TestZSKAuthenticatesFurtherTransactionsOnceRegistered(t *testing.T) {
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
		t.Fatalf("ZSK registration rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	// A routine content push, authenticated by the ZSK alone.
	now := time.Now()
	signedA, err := SignZoneContent([]dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, zsk, zskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	partial := new(dns.Msg)
	partial.SetQuestion("example.org.", dns.TypeSOA)
	partial.Opcode = dns.OpcodeUpdate
	partial.Insert(signedA)
	wire, err := SignUpdate(partial, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	resp := sendRaw(t, addr, wire)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ZSK-authenticated push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	answer := query(t, addr, "www.example.org.", dns.TypeA)
	if len(answer.Answer) != 1 {
		t.Fatalf("expected the ZSK-authenticated push's content to be servable, got %d answers", len(answer.Answer))
	}
}

// TestServeUpdateAuditTrailAttributesEachPushToItsOwnZSK proves the
// audit trail's key-tag/key-role attribution (AuditEntry.KeyTag/
// KeyRole) actually answers "which signer pushed this" for an HA/
// multi-signer deployment: two independently registered ZSKs -- each
// standing in for a different signer machine, holding its own key --
// get their own content pushes attributed to their own key tag and
// "ZSK" role, never confused with each other or with the KSK that
// registered both.
func TestServeUpdateAuditTrailAttributesEachPushToItsOwnZSK(t *testing.T) {
	s := newTestSazu("example.org.")
	s.DB = openTestDB(t)
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	onboardWithKSK(t, addr, ksk, kskPriv)

	zskA, zskAPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK A: %v", err)
	}
	if resp := addZSK(t, addr, ksk, kskPriv, zskA); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("registering ZSK A rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	zskB, zskBPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK B: %v", err)
	}
	if resp := addZSK(t, addr, ksk, kskPriv, zskB); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("registering ZSK B rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	pushContent := func(zsk *dns.DNSKEY, zskPriv ed25519.PrivateKey, rr dns.RR) {
		t.Helper()
		now := time.Now()
		signed, err := SignZoneContent([]dns.RR{rr}, zsk, zskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
		if err != nil {
			t.Fatalf("SignZoneContent: %v", err)
		}
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeSOA)
		m.Opcode = dns.OpcodeUpdate
		m.Insert(signed)
		wire, err := SignUpdate(m, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatalf("signing: %v", err)
		}
		if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("content push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
		}
	}
	pushContent(zskA, zskAPriv, testA("a.example.org.", net.IPv4(203, 0, 113, 10)))
	pushContent(zskB, zskBPriv, testA("b.example.org.", net.IPv4(203, 0, 113, 20)))

	entries, err := s.DB.RecentTransactions("example.org.", 10)
	if err != nil {
		t.Fatalf("RecentTransactions: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 audit entries (onboarding, 2 ZSK registrations, 2 content pushes), got %d: %+v", len(entries), entries)
	}
	// Newest first.
	pushB, pushA, addB, addA, onboarding := entries[0], entries[1], entries[2], entries[3], entries[4]

	if pushB.KeyTag == nil || *pushB.KeyTag != zskB.KeyTag() || pushB.KeyRole != "ZSK" {
		t.Fatalf("expected the push signed by ZSK B to be attributed to its own key tag, got %+v", pushB)
	}
	if pushA.KeyTag == nil || *pushA.KeyTag != zskA.KeyTag() || pushA.KeyRole != "ZSK" {
		t.Fatalf("expected the push signed by ZSK A to be attributed to its own key tag, got %+v", pushA)
	}
	if pushA.KeyTag != nil && pushB.KeyTag != nil && *pushA.KeyTag == *pushB.KeyTag {
		t.Fatalf("expected ZSK A and ZSK B's pushes to carry distinct key tags, both got %d", *pushA.KeyTag)
	}
	// Both ZSK-registration pushes were authenticated by the KSK (the
	// already-trusted key doing the registering), not by the new ZSK
	// being registered -- a ZSK is never trusted to vouch for itself.
	if addA.KeyTag == nil || *addA.KeyTag != ksk.KeyTag() || addA.KeyRole != "KSK" {
		t.Fatalf("expected ZSK A's registration to be attributed to the KSK that authorized it, got %+v", addA)
	}
	if addB.KeyTag == nil || *addB.KeyTag != ksk.KeyTag() || addB.KeyRole != "KSK" {
		t.Fatalf("expected ZSK B's registration to be attributed to the KSK that authorized it, got %+v", addB)
	}
	if onboarding.KeyTag == nil || *onboarding.KeyTag != ksk.KeyTag() || onboarding.KeyRole != "KSK" {
		t.Fatalf("expected onboarding to be attributed to the KSK, got %+v", onboarding)
	}
}

// TestZSKCanSignContentVerifiedUnderRequireValidRRSIGs proves the ZSK is
// a real content-signing key, not just a transaction-authentication
// identity: content signed by the ZSK (rather than the KSK) still
// verifies, because VerifySignedRRsets is given the zone's whole current
// content-signer set, KSK and ZSK alike.
func TestZSKCanSignContentVerifiedUnderRequireValidRRSIGs(t *testing.T) {
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
		t.Fatalf("ZSK registration rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	rrs := []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}
	now := time.Now()
	signed, err := SignZoneContent(rrs, zsk, zskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("signing content with the ZSK: %v", err)
	}
	partial := new(dns.Msg)
	partial.SetQuestion("example.org.", dns.TypeSOA)
	partial.Opcode = dns.OpcodeUpdate
	partial.Insert(signed)
	wire, err := SignUpdate(partial, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing transaction: %v", err)
	}
	resp := sendRaw(t, addr, wire)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR (content signed by a registered ZSK should verify)", dns.RcodeToString[resp.Rcode])
	}
}

// TestZSKCanBeRetired proves the reverse of registration: retiring a ZSK
// removes it from the zone's trusted key set, and it no longer
// authenticates anything afterward.
func TestZSKCanBeRetired(t *testing.T) {
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
		t.Fatalf("ZSK registration rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if resp := retireZSK(t, addr, ksk, kskPriv, zsk); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ZSK retirement rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	zk, _ := s.Keys.Get("example.org.")
	if len(zk.ZSKs) != 0 {
		t.Fatalf("expected no ZSKs left after retiring the only one, got %+v", zk.ZSKs)
	}

	// The retired ZSK's own signature no longer authenticates anything.
	partial := new(dns.Msg)
	partial.SetQuestion("example.org.", dns.TypeSOA)
	partial.Opcode = dns.OpcodeUpdate
	partial.Insert([]dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))})
	now := time.Now()
	wire, err := SignUpdate(partial, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	resp := sendRaw(t, addr, wire)
	if resp.Rcode == dns.RcodeSuccess {
		t.Fatalf("expected a push authenticated by a retired ZSK to be rejected")
	}
}

// TestKSKRolloverPreservesExistingZSK proves KeyRegistry.PinKSK's own
// documented guarantee end to end: rolling the KSK over does not
// invalidate a ZSK registered under the old one -- it keeps
// authenticating transactions immediately afterward, with no re-
// registration needed.
func TestKSKRolloverPreservesExistingZSK(t *testing.T) {
	s := newTestSazu("example.org.")
	s.InsecureSkipChainValidation = false
	s.Validator = fakeValidator{err: nil} // the new KSK's DS "checks out"
	addr := serveThroughRealServer(t, s)

	oldKSK, oldKSKPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating old KSK: %v", err)
	}
	onboardWithKSK(t, addr, oldKSK, oldKSKPriv)

	zsk, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	if resp := addZSK(t, addr, oldKSK, oldKSKPriv, zsk); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("ZSK registration rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	newKSK, newKSKPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating new KSK: %v", err)
	}
	newKSKRR := &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: newKSK.Flags, Protocol: newKSK.Protocol, Algorithm: newKSK.Algorithm, PublicKey: newKSK.PublicKey,
	}
	now := time.Now()
	signedKSK, err := SignZoneContent([]dns.RR{newKSKRR}, newKSK, newKSKPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	rollover := new(dns.Msg)
	rollover.SetQuestion("example.org.", dns.TypeSOA)
	rollover.Opcode = dns.OpcodeUpdate
	rollover.Insert(signedKSK)
	rolloverWire, err := SignUpdate(rollover, newKSK, newKSKPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing rollover push: %v", err)
	}
	if resp := sendRaw(t, addr, rolloverWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rollover push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	zk, ok := s.Keys.Get("example.org.")
	if !ok || zk.KSK.DNSKEY.PublicKey != newKSK.PublicKey {
		t.Fatalf("expected the KSK to have rolled over")
	}
	if len(zk.ZSKs) != 1 || zk.ZSKs[0].DNSKEY.PublicKey != zsk.PublicKey {
		t.Fatalf("expected the ZSK to survive the KSK rollover untouched, got %+v", zk.ZSKs)
	}

	// The ZSK, registered under the now-superseded KSK, still
	// authenticates a push on its own.
	now = time.Now()
	signedA, err := SignZoneContent([]dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, zsk, zskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	partial := new(dns.Msg)
	partial.SetQuestion("example.org.", dns.TypeSOA)
	partial.Opcode = dns.OpcodeUpdate
	partial.Insert(signedA)
	wire, err := SignUpdate(partial, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	resp := sendRaw(t, addr, wire)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("post-rollover ZSK-authenticated push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
}

// TestFirstContactRejectsNonKSKCandidate proves a zone can only ever be
// established (first contact) by a SEP-flagged (KSK) key -- a candidate
// presented without that flag is refused with a specific diagnostic, and
// pins nothing.
func TestFirstContactRejectsNonKSKCandidate(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	zskShaped, zskPriv, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	onboard, err := BuildFullZonePush("example.org.", testSOA(1), nil, zskShaped, zskPriv, nil)
	if err != nil {
		t.Fatalf("building push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(onboard, zskShaped, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	resp := sendRaw(t, addr, wire)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if status, ok := diagnosticStatus(resp); !ok || status != statusErrFirstContactNeedsKSK {
		t.Fatalf("expected %s diagnostic, got status=%q ok=%v", statusErrFirstContactNeedsKSK, status, ok)
	}
	if _, pinned := s.Keys.Get("example.org."); pinned {
		t.Fatalf("expected no key to be pinned for a rejected first-contact push")
	}
}

// TestAddZSKRejectsWeakAlgorithm proves §10.7's algorithm floor applies
// to a ZSK registration exactly as it does at first contact and KSK
// rollover -- checked before the key is registered.
func TestAddZSKRejectsWeakAlgorithm(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	onboardWithKSK(t, addr, ksk, kskPriv)

	weakZSK := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     dns.ZONE, // ZSK-shaped, no SEP
		Protocol:  3,
		Algorithm: dns.RSAMD5, // well below the floor
		PublicKey: "AAAA",
	}
	resp := addZSK(t, addr, ksk, kskPriv, weakZSK)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if status, ok := diagnosticStatus(resp); !ok || status != statusErrWeakAlgorithm {
		t.Fatalf("expected %s diagnostic, got status=%q ok=%v", statusErrWeakAlgorithm, status, ok)
	}

	zk, _ := s.Keys.Get("example.org.")
	if len(zk.ZSKs) != 0 {
		t.Fatalf("expected the weak-algorithm ZSK to not be registered, got %+v", zk.ZSKs)
	}
}
