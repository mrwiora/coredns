package sazu

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signAt signs m with key at a fixed inception, so tests control exactly
// which SIG(0) inception each message carries.
func signAt(t *testing.T, m *dns.Msg, key *dns.DNSKEY, priv ed25519.PrivateKey, inception time.Time) []byte {
	t.Helper()
	wire, err := SignUpdate(m, key, priv, inception, inception.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	return wire
}

// TestReplayedMessageIsRejected: the exact same signed bytes are
// accepted once, never twice.
func TestReplayedMessageIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	s.Replay = NewReplayGuard()
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	m, err := BuildContentPush("example.org.", testSOA(5), []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	wire := signAt(t, m, zsk, zskPriv, time.Now().Add(-time.Minute))
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first delivery rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	expectRefusedWith(t, "replayed delivery", sendRaw(t, addr, wire), dns.RcodeRefused, statusErrReplayed)
}

// TestReplayedAddZSKCannotUnretireAKey is the motivating attack from the
// threat model: capture a KSK-signed add-zsk, wait for that ZSK to be
// retired, replay the capture. With per-key monotonic inception the
// replay is older than the retirement, and refused.
func TestReplayedAddZSKCannotUnretireAKey(t *testing.T) {
	s := newTestSazu("example.org.")
	s.Replay = NewReplayGuard()
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)

	extra, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	base := time.Now().Add(-time.Minute)

	add, err := BuildAddZSKPush("example.org.", currentDNSKEYs(t, addr), extra, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildAddZSKPush: %v", err)
	}
	captured := signAt(t, add, ksk, kskPriv, base.Add(1*time.Second))
	if resp := sendRaw(t, addr, captured); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	retire, err := BuildRetireZSKPush("example.org.", currentDNSKEYs(t, addr), extra, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildRetireZSKPush: %v", err)
	}
	if resp := sendRaw(t, addr, signAt(t, retire, ksk, kskPriv, base.Add(2*time.Second))); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("retire-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	expectRefusedWith(t, "replayed add-zsk", sendRaw(t, addr, captured), dns.RcodeRefused, statusErrReplayed)
	if zk, _ := s.Keys.Get("example.org."); func() bool { _, ok := zk.FindZSK(extra.KeyTag()); return ok }() {
		t.Fatalf("expected the retired ZSK to stay retired")
	}
}

// TestDelayedOlderMessageIsRejected: a message held back and delivered
// after a newer one from the same key is refused, even though it was
// never delivered before -- ordering, not just duplication, is enforced.
func TestDelayedOlderMessageIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	s.Replay = NewReplayGuard()
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	base := time.Now().Add(-time.Minute)
	build := func(serial uint32) *dns.Msg {
		m, err := BuildContentPush("example.org.", testSOA(serial), nil, zsk, zskPriv, nil)
		if err != nil {
			t.Fatalf("BuildContentPush: %v", err)
		}
		return m
	}
	older := signAt(t, build(100), zsk, zskPriv, base.Add(1*time.Second))
	newer := signAt(t, build(50), zsk, zskPriv, base.Add(2*time.Second))
	if resp := sendRaw(t, addr, newer); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("newer push rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	expectRefusedWith(t, "held-back older push", sendRaw(t, addr, older), dns.RcodeRefused, statusErrReplayed)
}

// TestReplayMarksSurviveRestartAndDecommission: marks are persisted
// with the update that set them and outlive the zone itself, so neither
// a restart nor a decommission reopens a replay window.
func TestReplayMarksSurviveRestartAndDecommission(t *testing.T) {
	db := openTestDB(t)
	s := newTestSazu("example.org.")
	s.Replay = NewReplayGuard()
	s.DB = db
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
	base := time.Now().Add(-time.Minute)
	onboardWire := signAt(t, trust, ksk, kskPriv, base.Add(1*time.Second))
	if resp := sendRaw(t, addr, onboardWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("publish-trust rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if resp := sendRaw(t, addr, signAt(t, BuildDecommissionPush("example.org."), ksk, kskPriv, base.Add(2*time.Second))); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("decommission rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	// A fresh server over the same database, as after a restart.
	marks, err := db.LoadReplayMarks()
	if err != nil {
		t.Fatalf("LoadReplayMarks: %v", err)
	}
	store, keys, contacts, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	s2 := newTestSazu("example.org.")
	s2.Store, s2.Keys, s2.Contacts, s2.DB = store, keys, contacts, db
	s2.Replay = NewReplayGuard()
	s2.Replay.Load(marks)
	addr2 := serveThroughRealServer(t, s2)

	expectRefusedWith(t, "replayed onboarding after decommission and restart", sendRaw(t, addr2, onboardWire), dns.RcodeRefused, statusErrReplayed)
	if _, ok := s2.Keys.Get("example.org."); ok {
		t.Fatalf("expected the replay to not re-onboard the zone")
	}
}

// TestOverlongSIG0LifetimeIsRejected: a SIG(0) valid for longer than the
// server's maximum is refused outright.
func TestOverlongSIG0LifetimeIsRejected(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)

	m, err := BuildContentPush("example.org.", testSOA(5), nil, zsk, zskPriv, nil)
	if err != nil {
		t.Fatalf("BuildContentPush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(m, zsk, zskPriv, now.Add(-time.Minute), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	expectRefusedWith(t, "day-long SIG(0)", sendRaw(t, addr, wire), dns.RcodeNotAuth, statusErrSIG0LifetimeTooLong)
}

// TestSameSecondMessagesAreAcceptedButNotReplayed: several different
// messages from one key within the same second (e.g. rotate-key's
// add-zsk then retire-zsk) are all accepted without the client having to
// wait, while replaying any of them is still refused -- also after a
// restart.
func TestSameSecondMessagesAreAcceptedButNotReplayed(t *testing.T) {
	db := openTestDB(t)
	s := newTestSazu("example.org.")
	s.Replay = NewReplayGuard()
	s.DB = db
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, zsk, _ := onboardKSKAndZSK(t, addr)

	extra, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	inception := time.Now().Add(-time.Minute).Truncate(time.Second)

	add, err := BuildAddZSKPush("example.org.", currentDNSKEYs(t, addr), extra, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildAddZSKPush: %v", err)
	}
	addWire := signAt(t, add, ksk, kskPriv, inception)
	if resp := sendRaw(t, addr, addWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	retire, err := BuildRetireZSKPush("example.org.", currentDNSKEYs(t, addr), zsk, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildRetireZSKPush: %v", err)
	}
	retireWire := signAt(t, retire, ksk, kskPriv, inception)
	if resp := sendRaw(t, addr, retireWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("same-second retire-zsk rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	expectRefusedWith(t, "replayed same-second add-zsk", sendRaw(t, addr, addWire), dns.RcodeRefused, statusErrReplayed)

	marks, err := db.LoadReplayMarks()
	if err != nil {
		t.Fatalf("LoadReplayMarks: %v", err)
	}
	store, keys, contacts, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	s2 := newTestSazu("example.org.")
	s2.Store, s2.Keys, s2.Contacts, s2.DB = store, keys, contacts, db
	s2.Replay = NewReplayGuard()
	s2.Replay.Load(marks)
	addr2 := serveThroughRealServer(t, s2)
	expectRefusedWith(t, "replayed retire-zsk after restart", sendRaw(t, addr2, retireWire), dns.RcodeRefused, statusErrReplayed)
	expectRefusedWith(t, "replayed add-zsk after restart", sendRaw(t, addr2, addWire), dns.RcodeRefused, statusErrReplayed)
}
