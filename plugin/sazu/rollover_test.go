package sazu

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newHoldDownTestSazu returns a Sazu with a 72h rollover hold-down, a
// chain-of-trust check that always passes (the new key's DS "is
// published"), and a controllable clock.
func newHoldDownTestSazu(t *testing.T) (*Sazu, *time.Time) {
	t.Helper()
	s := newTestSazu("example.org.")
	s.InsecureSkipChainValidation = false
	s.Validator = fakeValidator{err: nil}
	s.Pending = NewPendingRollovers()
	s.RolloverHoldDown = DefaultRolloverHoldDown
	clock := time.Now()
	s.now = func() time.Time { return clock }
	return s, &clock
}

func coSignedRollover(t *testing.T, addr string, oldKSK *dns.DNSKEY, oldPriv ed25519.PrivateKey, newKSK *dns.DNSKEY, newPriv ed25519.PrivateKey) *dns.Msg {
	t.Helper()
	m, err := BuildKSKRolloverPushCoSigned("example.org.", currentDNSKEYs(t, addr), oldKSK, oldPriv, newKSK, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	return sendRaw(t, addr, signNow(t, m, newKSK, newPriv))
}

func pinnedKSK(t *testing.T, s *Sazu) *dns.DNSKEY {
	t.Helper()
	zk, ok := s.Keys.Get("example.org.")
	if !ok {
		t.Fatalf("zone not pinned")
	}
	return zk.KSK.DNSKEY
}

// TestCoSignedRolloverAppliesImmediately: with the old KSK's consent, no
// hold-down -- and the co-signature isn't served afterwards.
func TestCoSignedRolloverAppliesImmediately(t *testing.T) {
	s, _ := newHoldDownTestSazu(t)
	addr := serveThroughRealServer(t, s)
	oldKSK, oldPriv, _, _ := onboardKSKAndZSK(t, addr)
	newKSK, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	if resp := coSignedRollover(t, addr, oldKSK, oldPriv, newKSK, newPriv); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("co-signed rollover rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if pinnedKSK(t, s).PublicKey != newKSK.PublicKey {
		t.Fatalf("expected the new KSK to be pinned")
	}
	z, _ := s.Store.Get("example.org.")
	for _, rr := range z.LookupRRSIG("example.org.", dns.TypeDNSKEY) {
		if rr.(*dns.RRSIG).KeyTag == oldKSK.KeyTag() {
			t.Fatalf("the old KSK's co-signature must not be stored or served")
		}
	}
}

// TestDSOnlyRolloverWaitsOutTheHoldDown: without the old KSK's
// co-signature, the first attempt only records a pending rollover, and
// the same rollover completes once re-sent after the hold-down.
func TestDSOnlyRolloverWaitsOutTheHoldDown(t *testing.T) {
	s, clock := newHoldDownTestSazu(t)
	addr := serveThroughRealServer(t, s)
	oldKSK, _, _, _ := onboardKSKAndZSK(t, addr)
	newKSK, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}

	resp := rolloverKSK(t, addr, oldKSK, newKSK, newPriv)
	expectRefusedWith(t, "first DS-only attempt", resp, dns.RcodeRefused, statusErrRolloverPending)
	if !strings.HasPrefix(diagnosticDetailForTest(resp), "not before ") {
		t.Fatalf("expected the earliest completion time in the detail, got %q", diagnosticDetailForTest(resp))
	}
	if pinnedKSK(t, s).PublicKey != oldKSK.PublicKey {
		t.Fatalf("a pending rollover must not change the pinned KSK")
	}

	*clock = clock.Add(DefaultRolloverHoldDown - time.Minute)
	expectRefusedWith(t, "attempt just before the hold-down ends", rolloverKSK(t, addr, oldKSK, newKSK, newPriv), dns.RcodeRefused, statusErrRolloverPending)

	*clock = clock.Add(2 * time.Minute)
	if resp := rolloverKSK(t, addr, oldKSK, newKSK, newPriv); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("attempt after the hold-down rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if pinnedKSK(t, s).PublicKey != newKSK.PublicKey {
		t.Fatalf("expected the new KSK to be pinned after the hold-down")
	}
	if _, pending := s.Pending.Get("example.org."); pending {
		t.Fatalf("expected the pending rollover to be cleared once completed")
	}
}

// TestCurrentKSKCancelsAPendingRollover: the explicit cancel directive
// (and, the same way, any other control change the current KSK
// authenticates) clears a pending rollover, so re-sending it after the
// hold-down only starts a new hold-down.
func TestCurrentKSKCancelsAPendingRollover(t *testing.T) {
	for _, via := range []string{"cancel-rollover", "contact"} {
		t.Run(via, func(t *testing.T) {
			s, clock := newHoldDownTestSazu(t)
			addr := serveThroughRealServer(t, s)
			oldKSK, oldPriv, _, _ := onboardKSKAndZSK(t, addr)
			attackerKSK, attackerPriv, err := GenerateEd25519Key("example.org.", true)
			if err != nil {
				t.Fatal(err)
			}
			expectRefusedWith(t, "attacker's first attempt", rolloverKSK(t, addr, oldKSK, attackerKSK, attackerPriv), dns.RcodeRefused, statusErrRolloverPending)

			var m *dns.Msg
			if via == "cancel-rollover" {
				m = BuildCancelRolloverPush("example.org.")
			} else {
				op, err := BuildContactOp("example.org.", []string{"mailto:owner@example.org"})
				if err != nil {
					t.Fatal(err)
				}
				m = new(dns.Msg)
				m.SetUpdate("example.org.")
				m.Insert([]dns.RR{op})
			}
			if resp := sendRaw(t, addr, signNow(t, m, oldKSK, oldPriv)); resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("%s by the current KSK rcode = %s", via, dns.RcodeToString[resp.Rcode])
			}
			if _, pending := s.Pending.Get("example.org."); pending {
				t.Fatalf("expected %s to cancel the pending rollover", via)
			}

			*clock = clock.Add(DefaultRolloverHoldDown + time.Hour)
			expectRefusedWith(t, "attacker's retry after the hold-down", rolloverKSK(t, addr, oldKSK, attackerKSK, attackerPriv), dns.RcodeRefused, statusErrRolloverPending)
			if pinnedKSK(t, s).PublicKey != oldKSK.PublicKey {
				t.Fatalf("expected the zone to stay pinned to the owner's KSK")
			}
		})
	}
}

// TestCancelRolloverRequiresTheKSK: a ZSK can't cancel (or otherwise
// interfere with) a pending rollover.
func TestCancelRolloverRequiresTheKSK(t *testing.T) {
	s, _ := newHoldDownTestSazu(t)
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)
	resp := sendRaw(t, addr, signNow(t, BuildCancelRolloverPush("example.org."), zsk, zskPriv))
	expectRefusedWith(t, "ZSK cancel-rollover", resp, dns.RcodeRefused, statusErrRequiresKSK)
}

// TestCoSignatureByAnotherKeyDoesNotSkipTheHoldDown: only the pinned
// KSK's co-signature counts.
func TestCoSignatureByAnotherKeyDoesNotSkipTheHoldDown(t *testing.T) {
	s, _ := newHoldDownTestSazu(t)
	addr := serveThroughRealServer(t, s)
	oldKSK, _, _, _ := onboardKSKAndZSK(t, addr)
	newKSK, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	impostor, impostorPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	// Claims to be the old KSK's co-signature, but made by another key
	// that merely borrows its key tag position in the builder.
	m, err := BuildKSKRolloverPushCoSigned("example.org.", currentDNSKEYs(t, addr), oldKSK, impostorPriv, newKSK, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	_ = impostor
	expectRefusedWith(t, "rollover with a forged co-signature", sendRaw(t, addr, signNow(t, m, newKSK, newPriv)), dns.RcodeRefused, statusErrRolloverPending)
}

// TestPendingRolloverSurvivesRestart: the hold-down's start is persisted,
// so a restart neither resets nor forgets it.
func TestPendingRolloverSurvivesRestart(t *testing.T) {
	db := openTestDB(t)
	s, clock := newHoldDownTestSazu(t)
	s.DB = db
	addr := serveThroughRealServer(t, s)
	oldKSK, _, _, _ := onboardKSKAndZSK(t, addr)
	newKSK, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	expectRefusedWith(t, "first attempt", rolloverKSK(t, addr, oldKSK, newKSK, newPriv), dns.RcodeRefused, statusErrRolloverPending)

	pending, err := db.LoadPendingRollovers()
	if err != nil {
		t.Fatal(err)
	}
	pr, ok := pending["example.org."]
	if !ok || pr.KSK.PublicKey != newKSK.PublicKey || pr.RequestedAt.Unix() != clock.Unix() {
		t.Fatalf("expected the pending rollover persisted, got %+v", pending)
	}
}

func diagnosticDetailForTest(m *dns.Msg) string {
	for _, rr := range m.Extra {
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 1 {
			return txt.Txt[1]
		}
	}
	return ""
}
