package sazu

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestStatusIsReportedAsExtendedDNSError: with EDNS(0) on the request,
// the SAZU status comes back as an RFC 8914 EDE (mapped INFO-CODE, the
// status as EXTRA-TEXT) as well as the TXT record; without EDNS, only
// the TXT -- RFC 6891 forbids an OPT record in that reply.
func TestStatusIsReportedAsExtendedDNSError(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardKSKAndZSK(t, addr)

	partial := func(edns bool) *dns.Msg {
		now := time.Now()
		signed, err := SignZoneContent([]dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, ksk, kskPriv,
			now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
		if err != nil {
			t.Fatal(err)
		}
		m := new(dns.Msg)
		m.SetUpdate("example.org.")
		m.Insert(signed)
		if edns {
			m.SetEdns0(dns.DefaultMsgSize, false)
		}
		wire, err := SignUpdate(m, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return sendRaw(t, addr, wire)
	}

	resp := partial(true)
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatalf("expected an OPT record in the reply to an EDNS request")
	}
	var ede *dns.EDNS0_EDE
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			ede = e
		}
	}
	if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeProhibited || ede.ExtraText != statusErrFullZoneRequired {
		t.Fatalf("expected EDE 18 with %q, got %+v", statusErrFullZoneRequired, ede)
	}
	if status, ok := diagnosticStatus(resp); !ok || status != statusErrFullZoneRequired {
		t.Fatalf("expected the TXT diagnostic too, got %q %v", status, ok)
	}

	resp = partial(false)
	if resp.IsEdns0() != nil {
		t.Fatalf("expected no OPT record in the reply to a request without EDNS")
	}
	if status, ok := diagnosticStatus(resp); !ok || status != statusErrFullZoneRequired {
		t.Fatalf("expected the TXT diagnostic, got %q %v", status, ok)
	}
}

// TestEveryStatusHasAnEDECode keeps edeCodes in step with the status
// codes: anything unmapped would silently be reported as 0 (Other).
func TestEveryStatusHasAnEDECode(t *testing.T) {
	other := map[string]bool{statusErrStaleSerial: true, statusErrStaleVersion: true, statusErrSIG0LifetimeTooLong: true}
	for _, st := range []string{
		statusErrNoDSPublished, statusErrUnknownSigner, statusErrSigInvalid, statusErrWeakAlgorithm, statusErrWeakDSDigest,
		statusErrQuotaExceeded, statusErrRateLimited, statusErrTransportNotAllowed, statusErrStaleSerial,
		statusErrFirstContactNeedsKSK, statusErrExpiredSignature, statusErrDecommissionRequiresKSK, statusErrRequiresKSK,
		statusErrFullZoneRequired, statusErrDNSKEYSetMismatch, statusErrVersionRequired, statusErrStaleVersion,
		statusErrSIG0LifetimeTooLong,
	} {
		if _, mapped := edeCodes[st]; !mapped && !other[st] {
			t.Errorf("status %s has no EDE mapping", st)
		}
	}
}

// TestSignatureFailureNamesTheRRset: the diagnostic detail says which
// name and type failed verification.
func TestSignatureFailureNamesTheRRset(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	_, _, zsk, zskPriv := onboardKSKAndZSK(t, addr)
	m, err := BuildContentPush("example.org.", testSOA(5), []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, zsk, zskPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Drop the RRSIG covering www's A record.
	var kept []dns.RR
	for _, rr := range m.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
			continue
		}
		kept = append(kept, rr)
	}
	m.Ns = kept
	resp := sendRaw(t, addr, signNow(t, m, zsk, zskPriv))
	expectRefusedWith(t, "push with an unsigned RRset", resp, dns.RcodeNotAuth, statusErrSigInvalid)
	if d := diagnosticDetailForTest(resp); d != "no valid RRSIG covers www.example.org./A" {
		t.Fatalf("detail = %q", d)
	}
}
