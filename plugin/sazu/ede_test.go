package sazu

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestStatusIsReportedAsExtendedDNSError: with EDNS(0) on the request,
// the SAZU status comes back as an RFC 8914 EDE (mapped INFO-CODE, the
// status as EXTRA-TEXT); without EDNS, only the RCODE -- RFC 6891 forbids
// an OPT record in that reply.
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
			wire, err := SignUpdate(m, ksk, kskPriv, now.Add(-time.Minute), now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			return sendRaw(t, addr, wire)
		}
		sig := &dns.SIG{RRSIG: dns.RRSIG{
			Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY},
			Algorithm: ksk.Algorithm, KeyTag: ksk.KeyTag(), SignerName: ksk.Hdr.Name,
			Inception: uint32(now.Add(-time.Minute).Unix()), Expiration: uint32(now.Add(time.Hour).Unix()),
		}}
		wire, err := sig.Sign(kskPriv, m)
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

	resp = partial(false)
	if resp.IsEdns0() != nil || len(resp.Extra) != 0 || resp.Rcode != dns.RcodeRefused {
		t.Fatalf("expected a bare REFUSED to a request without EDNS, got %v", resp)
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
	expectRefusedWith(t, "push with an unsigned RRset", resp, dns.RcodeRefused, statusErrSigInvalid)
	if d := diagnosticDetailForTest(resp); d != "no valid RRSIG covers www.example.org./A" {
		t.Fatalf("detail = %q", d)
	}
}
