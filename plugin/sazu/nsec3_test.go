package sazu

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testNSEC3Param(iterations uint16, salt string) *dns.NSEC3PARAM {
	return &dns.NSEC3PARAM{Hash: dns.SHA1, Iterations: iterations, Salt: salt}
}

func TestNSEC3HashIsDeterministicAndLowercase(t *testing.T) {
	param := testNSEC3Param(0, "")
	h1 := NSEC3Hash("www.example.org.", param)
	h2 := NSEC3Hash("WWW.EXAMPLE.ORG.", param) // name hashing is case-insensitive, per RFC 5155 §5
	if h1 != h2 {
		t.Fatalf("expected case-insensitive hashing, got %q vs %q", h1, h2)
	}
	if h1 != strings.ToLower(h1) {
		t.Fatalf("expected a lowercase hash, got %q", h1)
	}
	if h1 == "" {
		t.Fatalf("expected a non-empty hash")
	}
}

func TestNSEC3HashDependsOnSaltAndIterations(t *testing.T) {
	base := NSEC3Hash("www.example.org.", testNSEC3Param(0, ""))
	if h := NSEC3Hash("www.example.org.", testNSEC3Param(1, "")); h == base {
		t.Fatalf("expected a different hash with a different iteration count")
	}
	if h := NSEC3Hash("www.example.org.", testNSEC3Param(0, "AABBCCDD")); h == base {
		t.Fatalf("expected a different hash with a different salt")
	}
}

// TestBuildNSEC3ChainCoversEveryOwnerAndCyclesByHash mirrors
// TestBuildNSECChainCoversEveryOwnerAndCycles (nsec_test.go): the
// synthesized chain visits every distinct owner name among adds exactly
// once and wraps back to its start, per RFC 5155 §7.1 -- ordered by hash
// value rather than name.
func TestBuildNSEC3ChainCoversEveryOwnerAndCyclesByHash(t *testing.T) {
	soa := testSOA(1)
	soa.Minttl = 1800
	adds := []dns.RR{
		soa,
		&dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1.example.org."},
		testA("www.example.org.", net.IPv4(203, 0, 113, 10)),
		testA("mx.example.org.", net.IPv4(203, 0, 113, 11)),
	}
	chain := BuildNSEC3Chain(soa, adds, NSEC3Options{})

	var params []*dns.NSEC3PARAM
	byOwner := make(map[string]*dns.NSEC3)
	for _, rr := range chain {
		switch v := rr.(type) {
		case *dns.NSEC3:
			if v.Hdr.Ttl != soa.Minttl {
				t.Fatalf("NSEC3 TTL = %d, want the SOA minimum %d", v.Hdr.Ttl, soa.Minttl)
			}
			byOwner[v.Hdr.Name] = v
		case *dns.NSEC3PARAM:
			params = append(params, v)
		default:
			t.Fatalf("BuildNSEC3Chain returned an unexpected record: %+v", rr)
		}
	}
	if len(params) != 1 {
		t.Fatalf("got %d NSEC3PARAM record(s), want exactly 1", len(params))
	}
	if len(byOwner) != 3 {
		t.Fatalf("got %d NSEC3 records, want 3 (apex, www, mx)", len(byOwner))
	}

	visited := map[string]bool{}
	var start string
	for owner := range byOwner {
		start = owner
		break
	}
	name := start
	for i := 0; i < len(byOwner); i++ {
		if visited[name] {
			t.Fatalf("chain revisited %s before covering all owners", name)
		}
		visited[name] = true
		next, ok := byOwner[name]
		if !ok {
			t.Fatalf("chain points at %s, which has no NSEC3 record", name)
		}
		name = next.NextDomain + "." + "example.org."
	}
	if name != start {
		t.Fatalf("chain did not cycle back to its start, ended at %s want %s", name, start)
	}
}

// TestBuildNSEC3ChainTypeBitmapReflectsContent mirrors
// TestBuildNSECChainTypeBitmapReflectsContent: each NSEC3's type bitmap
// lists exactly the RRset types present at that name (plus RRSIG, and --
// apex only -- NSEC3PARAM), never NSEC3 itself.
func TestBuildNSEC3ChainTypeBitmapReflectsContent(t *testing.T) {
	soa := testSOA(1)
	dnskeyRR := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}}
	ns := &dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: "ns1.example.org."}
	adds := []dns.RR{soa, dnskeyRR, ns, testA("www.example.org.", net.IPv4(203, 0, 113, 10))}

	chain := BuildNSEC3Chain(soa, adds, NSEC3Options{})
	param := testNSEC3Param(0, "")
	var apex, www *dns.NSEC3
	for _, rr := range chain {
		n, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		switch n.Hdr.Name {
		case NSEC3Hash("example.org.", param) + ".example.org.":
			apex = n
		case NSEC3Hash("www.example.org.", param) + ".example.org.":
			www = n
		}
	}
	if apex == nil || www == nil {
		t.Fatalf("expected NSEC3 records at both the hashed apex and hashed www")
	}
	assertSortedTypesEqual(t, apex.TypeBitMap, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeNSEC3PARAM, dns.TypeRRSIG})
	assertSortedTypesEqual(t, www.TypeBitMap, []uint16{dns.TypeA, dns.TypeRRSIG})
}

func TestBuildNSEC3ChainOptOutSetsFlagOnEveryRecord(t *testing.T) {
	soa := testSOA(1)
	chain := BuildNSEC3Chain(soa, []dns.RR{soa, testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, NSEC3Options{OptOut: true})
	found := 0
	for _, rr := range chain {
		if n, ok := rr.(*dns.NSEC3); ok {
			found++
			if n.Flags != 1 {
				t.Fatalf("NSEC3 at %s: Flags = %d, want 1 (Opt-Out)", n.Hdr.Name, n.Flags)
			}
		}
	}
	if found == 0 {
		t.Fatalf("expected at least one NSEC3 record")
	}
}

func TestBuildNSEC3ChainParamReflectsOptions(t *testing.T) {
	soa := testSOA(1)
	chain := BuildNSEC3Chain(soa, []dns.RR{soa}, NSEC3Options{Iterations: 7, Salt: "AABBCCDD"})
	for _, rr := range chain {
		if p, ok := rr.(*dns.NSEC3PARAM); ok {
			if p.Iterations != 7 || p.Salt != "AABBCCDD" || p.Hash != dns.SHA1 {
				t.Fatalf("got NSEC3PARAM %+v, want Iterations=7 Salt=AABBCCDD Hash=SHA1", p)
			}
			return
		}
	}
	t.Fatalf("expected an NSEC3PARAM record in the chain")
}

func TestNextCloserName(t *testing.T) {
	cases := []struct{ qname, ce, want string }{
		{"a.b.c.example.org.", "example.org.", "c.example.org."},
		{"missing.example.org.", "example.org.", "missing.example.org."},
	}
	for _, c := range cases {
		if got := NextCloserName(c.qname, c.ce); got != c.want {
			t.Fatalf("NextCloserName(%q, %q) = %q, want %q", c.qname, c.ce, got, c.want)
		}
	}
}

func TestCoveringHashFindsPredecessorAndWraps(t *testing.T) {
	sorted := []string{"1000", "5000", "9000"}
	if h, ok := CoveringHash("6000", sorted); !ok || h != "5000" {
		t.Fatalf("got h=%q ok=%v, want 5000", h, ok)
	}
	if h, ok := CoveringHash("0500", sorted); !ok || h != "9000" {
		t.Fatalf("got h=%q ok=%v, want 9000 (wrap-around)", h, ok)
	}
	if _, ok := CoveringHash("anything", nil); ok {
		t.Fatalf("expected ok=false for an empty chain")
	}
}

// onboardExampleOrgNSEC3 mirrors onboardExampleOrg (handler_test.go) but
// pushes with BuildFullZonePushNSEC3 instead of plain NSEC.
func onboardExampleOrgNSEC3(t *testing.T, addr string, opts NSEC3Options) *dns.DNSKEY {
	t.Helper()
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	rrs := []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}
	push, err := BuildFullZonePushNSEC3("example.org.", soa, rrs, key, priv, nil, opts)
	if err != nil {
		t.Fatalf("building push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(push, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	return key
}

func splitNSEC3AndRRSIGs(rrs []dns.RR) ([]*dns.NSEC3, map[string]*dns.RRSIG) {
	var nsec3s []*dns.NSEC3
	sigs := make(map[string]*dns.RRSIG)
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC3 {
				sigs[strings.ToLower(v.Hdr.Name)] = v
			}
		}
	}
	return nsec3s, sigs
}

// TestNODATACarriesValidNSEC3Proof mirrors TestNODATACarriesValidNSECProof
// (handler_test.go), for a zone onboarded with NSEC3 instead: the NSEC3
// matching the queried name's hash is what's served, and it genuinely
// verifies.
func TestNODATACarriesValidNSEC3Proof(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	key := onboardExampleOrgNSEC3(t, addr, NSEC3Options{})

	resp := queryDO(t, addr, "www.example.org.", dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("expected NOERROR/NODATA, got rcode=%s answer=%+v", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
	n3s, sigs := splitNSEC3AndRRSIGs(resp.Ns)
	param := testNSEC3Param(0, "")
	wantOwner := NSEC3Hash("www.example.org.", param) + ".example.org."
	if len(n3s) != 1 || n3s[0].Hdr.Name != wantOwner {
		t.Fatalf("expected exactly one NSEC3, at %s, got %+v", wantOwner, n3s)
	}
	sig, ok := sigs[wantOwner]
	if !ok {
		t.Fatalf("expected a covering RRSIG for www's NSEC3, got %+v", resp.Ns)
	}
	if err := sig.Verify(key, []dns.RR{n3s[0]}); err != nil {
		t.Fatalf("www's NSEC3 RRSIG does not verify: %v", err)
	}
}

// TestNXDOMAINCarriesValidNSEC3Proof mirrors TestNXDOMAINCarriesValidNSECProof,
// for a zone onboarded with NSEC3: up to three NSEC3 records (closest
// encloser match, next-closer-name cover, wildcard cover), each with a
// genuinely verifying RRSIG, and the closest-encloser one is an exact
// hash match for the zone apex (the actual closest encloser of any name
// under a two-name zone with no deeper structure).
func TestNXDOMAINCarriesValidNSEC3Proof(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	key := onboardExampleOrgNSEC3(t, addr, NSEC3Options{})

	resp := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	n3s, sigs := splitNSEC3AndRRSIGs(resp.Ns)
	if len(n3s) == 0 {
		t.Fatalf("expected at least one NSEC3 in authority, got %+v", resp.Ns)
	}
	param := testNSEC3Param(0, "")
	apexOwner := NSEC3Hash("example.org.", param) + ".example.org."
	var sawClosestEncloser bool
	for _, n := range n3s {
		sig, ok := sigs[strings.ToLower(n.Hdr.Name)]
		if !ok {
			t.Fatalf("NSEC3 at %s has no covering RRSIG in the response", n.Hdr.Name)
		}
		if err := sig.Verify(key, []dns.RR{n}); err != nil {
			t.Fatalf("NSEC3 at %s's RRSIG does not verify: %v", n.Hdr.Name, err)
		}
		if strings.EqualFold(n.Hdr.Name, apexOwner) {
			sawClosestEncloser = true
		}
	}
	if !sawClosestEncloser {
		t.Fatalf("expected the closest-encloser (apex) NSEC3 %s among %+v", apexOwner, n3s)
	}
}

// TestPartialPushInvalidatesNSEC3UntilNextFullPush mirrors
// TestPartialPushInvalidatesNSECUntilNextFullPush for the NSEC3 case:
// PurgeNSEC purges NSEC3(PARAM) too, so a partial push right after an
// NSEC3 onboarding still leaves the zone with no denial-of-existence
// proof at all until the next full push.
func TestPartialPushInvalidatesNSEC3UntilNextFullPush(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	rrs := []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}
	fullPush := func() {
		t.Helper()
		push, err := BuildFullZonePushNSEC3("example.org.", soa, rrs, key, priv, nil, NSEC3Options{})
		if err != nil {
			t.Fatalf("building full push: %v", err)
		}
		now := time.Now()
		wire, err := SignUpdate(push, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatalf("signing full push: %v", err)
		}
		if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("full push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
		}
	}
	fullPush() // onboards the zone

	before := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if n3s, _ := splitNSEC3AndRRSIGs(before.Ns); len(n3s) == 0 {
		t.Fatalf("expected a full push to leave a usable NSEC3 chain, got none")
	}

	now := time.Now()
	signedMail, err := SignZoneContent([]dns.RR{testA("mail.example.org.", net.IPv4(203, 0, 113, 20))}, key, priv, now.Add(-DefaultSignatureInceptionSkew), now.Add(DefaultSignatureValidity))
	if err != nil {
		t.Fatalf("SignZoneContent: %v", err)
	}
	update := new(dns.Msg)
	update.SetUpdate("example.org.")
	update.Insert(signedMail)
	wire, err := SignUpdate(update, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing partial update: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("partial push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	during := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if n3s, _ := splitNSEC3AndRRSIGs(during.Ns); len(n3s) != 0 {
		t.Fatalf("expected the partial push to invalidate the NSEC3 chain, still got %+v", n3s)
	}

	fullPush() // recomputes the chain from the same rrs given to BuildFullZonePushNSEC3

	after := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if n3s, _ := splitNSEC3AndRRSIGs(after.Ns); len(n3s) == 0 {
		t.Fatalf("expected a subsequent full push to restore the NSEC3 chain, got none")
	}
}
