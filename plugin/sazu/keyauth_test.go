package sazu

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// onboardKSKAndZSK onboards example.org. the way sazuctl publish-trust
// does (a KSK and its paired ZSK, no content) and returns both keys.
func onboardKSKAndZSK(t *testing.T, addr string) (ksk *dns.DNSKEY, kskPriv ed25519.PrivateKey, zsk *dns.DNSKEY, zskPriv ed25519.PrivateKey) {
	t.Helper()
	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zsk, zskPriv, err = GenerateEd25519Key("example.org.", false)
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
	return ksk, kskPriv, zsk, zskPriv
}

func expectRefusedWith(t *testing.T, what string, resp *dns.Msg, rcode int, status string) {
	t.Helper()
	if resp.Rcode != rcode {
		t.Fatalf("%s rcode = %s, want %s", what, dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
	}
	if got, ok := diagnosticStatus(resp); !ok || got != status {
		t.Fatalf("%s: expected %s diagnostic, got status=%q ok=%v", what, status, got, ok)
	}
}

// TestZSKCannotRegisterAnotherZSK: registering a ZSK changes the DNSKEY
// RRset, which only the KSK may do -- both because a stolen ZSK must not
// be able to plant a persistent key of its own, and because a DNSKEY
// RRset signed by a ZSK is bogus for every validating resolver.
func TestZSKCannotRegisterAnotherZSK(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	other, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	expectRefusedWith(t, "ZSK-authenticated add-zsk", addZSK(t, addr, zsk, zskPriv, other), dns.RcodeRefused, statusErrRequiresKSK)

	zk, _ := s.Keys.Get("example.org.")
	if _, registered := zk.FindZSK(other.KeyTag()); registered {
		t.Fatalf("expected the ZSK-authenticated registration to have no effect")
	}
	if got := len(currentDNSKEYs(t, addr)); got != 2 {
		t.Fatalf("expected the served DNSKEY RRset to stay at 2 keys, got %d", got)
	}
}

// TestZSKCannotRetireAZSK: the reverse -- a stolen ZSK must not be able
// to lock the legitimate signers out by retiring their keys.
func TestZSKCannotRetireAZSK(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	expectRefusedWith(t, "ZSK-authenticated retire-zsk", retireZSK(t, addr, zsk, zskPriv, zsk), dns.RcodeRefused, statusErrRequiresKSK)
	zk, _ := s.Keys.Get("example.org.")
	if _, registered := zk.FindZSK(zsk.KeyTag()); !registered {
		t.Fatalf("expected the ZSK to still be registered")
	}
}

// TestZSKCannotChangeContact: the registered contact is where
// sazu-watchd's alerts go, so changing it is KSK-only too.
func TestZSKCannotChangeContact(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	send := func(key *dns.DNSKEY, priv ed25519.PrivateKey, address string) *dns.Msg {
		t.Helper()
		op, err := BuildContactOp("example.org.", []string{address})
		if err != nil {
			t.Fatalf("BuildContactOp: %v", err)
		}
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeSOA)
		m.Opcode = dns.OpcodeUpdate
		m.Insert([]dns.RR{op})
		now := time.Now()
		wire, err := SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatalf("SignUpdate: %v", err)
		}
		return sendRaw(t, addr, wire)
	}

	if resp := send(ksk, kskPriv, "mailto:owner@example.org"); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("KSK contact registration rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	expectRefusedWith(t, "ZSK contact change", send(zsk, zskPriv, "mailto:attacker@example.net"), dns.RcodeRefused, statusErrRequiresKSK)
	if addrs, _ := s.Contacts.Get("example.org."); len(addrs) != 1 || addrs[0] != "mailto:owner@example.org" {
		t.Fatalf("expected the contact to be unchanged, got %v", addrs)
	}
}

// TestDNSKEYRRsetSignedByZSKIsRejected: even with the KSK authenticating
// the transaction, an RRSIG over the DNSKEY RRset must itself come from
// the KSK -- the only key a validating resolver will accept for it.
func TestDNSKEYRRsetSignedByZSKIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	other, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	// DNSKEY RRset re-signed by the ZSK...
	m, err := BuildAddZSKPush("example.org.", currentDNSKEYs(t, addr), other, zsk, zskPriv)
	if err != nil {
		t.Fatalf("BuildAddZSKPush: %v", err)
	}
	// ...but the transaction authenticated by the KSK.
	now := time.Now()
	wire, err := SignUpdate(m, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	expectRefusedWith(t, "ZSK-signed DNSKEY RRset", sendRaw(t, addr, wire), dns.RcodeNotAuth, statusErrSigInvalid)
}

// TestExtraUnverifiableRRSIGIsRejected: a valid KSK signature over the
// DNSKEY RRset doesn't carry along a second, ZSK-made one -- every RRSIG
// an update adds must itself verify against a key allowed to sign what
// it covers, or it would be stored and served next to the valid one.
func TestExtraUnverifiableRRSIGIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	other, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	current := currentDNSKEYs(t, addr)
	m, err := BuildAddZSKPush("example.org.", current, other, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildAddZSKPush: %v", err)
	}
	var keys []dns.RR
	for _, k := range append(current, other) {
		keys = append(keys, dnskeyRRAt("example.org.", k))
	}
	now := time.Now()
	zskSigned, err := SignZoneContent(keys, zsk, zskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	for _, rr := range zskSigned {
		if _, ok := rr.(*dns.RRSIG); ok {
			m.Insert([]dns.RR{rr})
		}
	}
	wire, err := SignUpdate(m, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeNotAuth {
		t.Fatalf("rcode = %s, want NOTAUTH", dns.RcodeToString[resp.Rcode])
	}
}

// TestIncompleteDNSKEYRRsetIsRejected: an update that adds a ZSK must
// carry -- and sign -- the complete resulting DNSKEY RRset. Adding just
// the new key with an RRSIG over it alone would leave the served RRset
// covered by a signature over something else.
func TestIncompleteDNSKEYRRsetIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)

	other, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	now := time.Now()
	signed, err := SignZoneContent([]dns.RR{dnskeyRRAt("example.org.", other)}, ksk, kskPriv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeSOA)
	m.Opcode = dns.OpcodeUpdate
	m.Insert(signed)
	wire, err := SignUpdate(m, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	expectRefusedWith(t, "delta-only add-zsk", sendRaw(t, addr, wire), dns.RcodeRefused, statusErrDNSKEYSetMismatch)
}

// TestRolloverCannotSlipInAnUnregisteredKey: a KSK rollover may only
// swap the KSK. A DNSKEY RRset that also carries some other key would be
// served without that key ever being registered.
func TestRolloverCannotSlipInAnUnregisteredKey(t *testing.T) {
	s := newTestSazu("example.org.")
	s.InsecureSkipChainValidation = false
	s.Validator = fakeValidator{err: nil}
	addr := serveThroughRealServer(t, s)
	oldKSK, _, _, _ := onboardKSKAndZSK(t, addr)

	newKSK, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	stray, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	m, err := BuildKSKRolloverPush("example.org.", append(currentDNSKEYs(t, addr), stray), oldKSK, newKSK, newPriv)
	if err != nil {
		t.Fatalf("BuildKSKRolloverPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(m, newKSK, newPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	expectRefusedWith(t, "rollover with a stray key", sendRaw(t, addr, wire), dns.RcodeRefused, statusErrDNSKEYSetMismatch)
	if zk, _ := s.Keys.Get("example.org."); zk.KSK.DNSKEY.PublicKey != oldKSK.PublicKey {
		t.Fatalf("expected the zone to stay pinned to the old KSK")
	}
}

// TestContentPushWithNonIncreasingSerialIsRejected: a full push can
// never install a SOA serial that isn't newer than the one served.
func TestContentPushWithNonIncreasingSerialIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	push := func(serial uint32, ip byte) *dns.Msg {
		t.Helper()
		m, err := BuildContentPush("example.org.", testSOA(serial), []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, ip))}, zsk, zskPriv, nil)
		if err != nil {
			t.Fatalf("BuildContentPush: %v", err)
		}
		now := time.Now()
		wire, err := SignUpdate(m, zsk, zskPriv, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatalf("SignUpdate: %v", err)
		}
		return sendRaw(t, addr, wire)
	}
	if resp := push(10, 10); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first push rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	expectRefusedWith(t, "same-serial push", push(10, 20), dns.RcodeRefused, statusErrStaleSerial)
	expectRefusedWith(t, "older-serial push", push(9, 30), dns.RcodeRefused, statusErrStaleSerial)
	if resp := push(11, 40); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("newer push rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	answer := query(t, addr, "www.example.org.", dns.TypeA)
	if len(answer.Answer) != 1 || !answer.Answer[0].(*dns.A).A.Equal(net.IPv4(203, 0, 113, 40)) {
		t.Fatalf("expected the newest push's content, got %+v", answer.Answer)
	}
}

func TestSerialGreater(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 1, false},
		{1, 2, false},
		{0, 0xFFFFFFFF, true}, // wraps around (RFC 1982)
		{0xFFFFFFFF, 0, false},
	}
	for _, c := range cases {
		if got := serialGreater(c.a, c.b); got != c.want {
			t.Errorf("serialGreater(%d, %d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestKSKRolloverWithSeveralZSKs: a rollover re-asserts every registered
// ZSK next to the new KSK; with more than one of them that must still be
// recognized as a rollover (it once wasn't -- any second non-SEP key
// counted as "more than one candidate").
func TestKSKRolloverWithSeveralZSKs(t *testing.T) {
	s := newTestSazu("example.org.")
	s.InsecureSkipChainValidation = false
	s.Validator = fakeValidator{err: nil}
	addr := serveThroughRealServer(t, s)
	oldKSK, oldPriv, _, _ := onboardKSKAndZSK(t, addr)

	second, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	if resp := addZSK(t, addr, oldKSK, oldPriv, second); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	newKSK, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	if resp := rolloverKSK(t, addr, oldKSK, newKSK, newPriv); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rollover rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	zk, _ := s.Keys.Get("example.org.")
	if zk.KSK.DNSKEY.PublicKey != newKSK.PublicKey || len(zk.ZSKs) != 2 {
		t.Fatalf("expected the new KSK pinned with both ZSKs kept, got KSK %d and %d ZSK(s)", zk.KSK.KeyTag(), len(zk.ZSKs))
	}
	if got := len(currentDNSKEYs(t, addr)); got != 3 {
		t.Fatalf("expected 3 served DNSKEYs (new KSK + 2 ZSKs), got %d", got)
	}
}
