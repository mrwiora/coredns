package sazu

import (
	"crypto/ed25519"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// lookupZoneRecords is a zone exercising every lookup path: a plain name,
// a CNAME, a DNAME, a wildcard, an empty non-terminal (b.deep, deep), an
// unsigned delegation with in-zone glue, and a signed delegation.
func lookupZoneRecords() []dns.RR {
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		return r
	}
	return []dns.RR{
		rr("example.org. 300 IN NS ns1.example.org."),
		rr("ns1.example.org. 300 IN A 192.0.2.53"),
		rr("www.example.org. 300 IN A 192.0.2.1"),
		rr("alias.example.org. 300 IN CNAME www.example.org."),
		rr("dn.example.org. 300 IN DNAME example.net."),
		rr("*.wild.example.org. 300 IN A 192.0.2.2"),
		rr("a.b.deep.example.org. 300 IN A 192.0.2.3"),
		rr("sub.example.org. 300 IN NS ns.sub.example.org."),
		rr("ns.sub.example.org. 300 IN A 192.0.2.54"),
		rr("sec.example.org. 300 IN NS ns.example.net."),
		rr("sec.example.org. 300 IN DS 12345 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
	}
}

type lookupFixture struct {
	s     *Sazu
	addr  string
	key   *dns.DNSKEY
	nsec3 bool
}

func newLookupFixture(t *testing.T, nsec3 bool) *lookupFixture {
	t.Helper()
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	soa := testSOA(1)
	soa.Minttl = 600 // below the SOA TTL, so RFC 2308/9077 TTLs are visible
	var m *dns.Msg
	if nsec3 {
		m, err = BuildFullZonePushNSEC3("example.org.", soa, lookupZoneRecords(), key, priv, nil, NSEC3Options{})
	} else {
		m, err = BuildFullZonePush("example.org.", soa, lookupZoneRecords(), key, priv, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp := sendRaw(t, addr, signNow(t, m, key, priv)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding rcode = %s (%v)", dns.RcodeToString[resp.Rcode], resp.Extra)
	}
	return &lookupFixture{s: s, addr: addr, key: key, nsec3: nsec3}
}

// verifyAllSigs checks every RRSIG in section verifies over the records
// it covers, by owner name and type, in that same section.
func (f *lookupFixture) verifyAllSigs(t *testing.T, section []dns.RR) {
	t.Helper()
	for _, rr := range section {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		var covered []dns.RR
		for _, c := range section {
			if c.Header().Rrtype == sig.TypeCovered && strings.EqualFold(c.Header().Name, sig.Hdr.Name) {
				covered = append(covered, c)
			}
		}
		if len(covered) == 0 {
			t.Fatalf("RRSIG at %s over %s has nothing to cover", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
		}
		if err := sig.Verify(f.key, covered); err != nil {
			t.Fatalf("RRSIG at %s over %s: %v", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], err)
		}
	}
}

func records[T dns.RR](section []dns.RR) []T {
	var out []T
	for _, rr := range section {
		if r, ok := rr.(T); ok {
			out = append(out, r)
		}
	}
	return out
}

// nsecCovers reports whether nsec proves name doesn't exist.
func nsecCovers(nsec *dns.NSEC, name string) bool {
	owner, next := nsec.Hdr.Name, nsec.NextDomain
	if CanonicalCompare(owner, next) < 0 {
		return CanonicalCompare(owner, name) < 0 && CanonicalCompare(name, next) < 0
	}
	return CanonicalCompare(owner, name) < 0 || CanonicalCompare(name, next) < 0 // wraps
}

// provesAbsent checks the authority section proves name doesn't exist.
func (f *lookupFixture) provesAbsent(t *testing.T, ns []dns.RR, name string) {
	t.Helper()
	if f.nsec3 {
		for _, n := range records[*dns.NSEC3](ns) {
			if n.Cover(name) {
				return
			}
		}
	} else {
		for _, n := range records[*dns.NSEC](ns) {
			if nsecCovers(n, name) {
				return
			}
		}
	}
	t.Fatalf("no record in the authority section proves %s absent: %v", name, ns)
}

// matchBitmap returns the bitmap of the NSEC/NSEC3 record matching name.
func (f *lookupFixture) matchBitmap(t *testing.T, ns []dns.RR, name string) []uint16 {
	t.Helper()
	if f.nsec3 {
		for _, n := range records[*dns.NSEC3](ns) {
			if n.Match(name) {
				return n.TypeBitMap
			}
		}
	} else {
		for _, n := range records[*dns.NSEC](ns) {
			if strings.EqualFold(n.Hdr.Name, name) {
				return n.TypeBitMap
			}
		}
	}
	t.Fatalf("no record in the authority section matches %s: %v", name, ns)
	return nil
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

func forBothChains(t *testing.T, fn func(t *testing.T, f *lookupFixture)) {
	for _, nsec3 := range []bool{false, true} {
		name := "NSEC"
		if nsec3 {
			name = "NSEC3"
		}
		t.Run(name, func(t *testing.T) { fn(t, newLookupFixture(t, nsec3)) })
	}
}

func TestLookupPositiveAnswerEchoesEDNSAndDO(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "www.example.org.", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(records[*dns.A](resp.Answer)) != 1 {
			t.Fatalf("got %v", resp)
		}
		if len(records[*dns.RRSIG](resp.Answer)) != 1 {
			t.Fatalf("expected the RRSIG with DO, got %v", resp.Answer)
		}
		f.verifyAllSigs(t, resp.Answer)
		opt := resp.IsEdns0()
		if opt == nil || !opt.Do() {
			t.Fatalf("expected an OPT record with DO echoed (RFC 6891, RFC 3225), got %v", opt)
		}
		if plain := query(t, f.addr, "www.example.org.", dns.TypeA); plain.IsEdns0() != nil || len(records[*dns.RRSIG](plain.Answer)) != 0 {
			t.Fatalf("a query without EDNS must get neither OPT nor RRSIGs: %v", plain)
		}
	})
}

func TestLookupCNAMEIsChased(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "alias.example.org.", dns.TypeA)
		if len(records[*dns.CNAME](resp.Answer)) != 1 || len(records[*dns.A](resp.Answer)) != 1 {
			t.Fatalf("expected CNAME then A, got %v", resp.Answer)
		}
		f.verifyAllSigs(t, resp.Answer)
		if cname := query(t, f.addr, "alias.example.org.", dns.TypeCNAME); len(cname.Answer) != 1 {
			t.Fatalf("a CNAME query gets only the CNAME, got %v", cname.Answer)
		}
	})
}

func TestLookupDNAMESynthesizesCNAME(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "x.y.dn.example.org.", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
		}
		dnames, cnames := records[*dns.DNAME](resp.Answer), records[*dns.CNAME](resp.Answer)
		if len(dnames) != 1 || len(cnames) != 1 || cnames[0].Target != "x.y.example.net." || cnames[0].Hdr.Name != "x.y.dn.example.org." {
			t.Fatalf("expected the DNAME and the synthesized CNAME (RFC 6672), got %v", resp.Answer)
		}
		sigs := records[*dns.RRSIG](resp.Answer)
		if len(sigs) != 1 || sigs[0].TypeCovered != dns.TypeDNAME {
			t.Fatalf("expected only the DNAME signed, got %v", sigs)
		}
	})
}

func TestLookupWildcard(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "foo.wild.example.org.", dns.TypeA)
		as := records[*dns.A](resp.Answer)
		if resp.Rcode != dns.RcodeSuccess || len(as) != 1 || as[0].Hdr.Name != "foo.wild.example.org." {
			t.Fatalf("expected a synthesized A (RFC 4592), got %v", resp)
		}
		sigs := records[*dns.RRSIG](resp.Answer)
		if len(sigs) != 1 || sigs[0].Labels != 3 {
			t.Fatalf("expected the wildcard's RRSIG with Labels=3, got %v", sigs)
		}
		f.verifyAllSigs(t, resp.Answer)
		// The next closer name must be proven absent (RFC 4035 §3.1.3.3,
		// RFC 5155 §7.2.6).
		f.provesAbsent(t, resp.Ns, "foo.wild.example.org.")

		nodata := queryDO(t, f.addr, "foo.wild.example.org.", dns.TypeMX)
		if nodata.Rcode != dns.RcodeSuccess || len(nodata.Answer) != 0 {
			t.Fatalf("expected a wildcard NODATA, got %v", nodata)
		}
		f.provesAbsent(t, nodata.Ns, "foo.wild.example.org.")
		if bm := f.matchBitmap(t, nodata.Ns, "*.wild.example.org."); hasType(bm, dns.TypeMX) || !hasType(bm, dns.TypeA) {
			t.Fatalf("wildcard bitmap %v", bm)
		}
	})
}

func TestLookupNXDOMAIN(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "nope.example.org.", dns.TypeA)
		if resp.Rcode != dns.RcodeNameError || !resp.Authoritative {
			t.Fatalf("got %v", resp)
		}
		soas := records[*dns.SOA](resp.Ns)
		if len(soas) != 1 || soas[0].Hdr.Ttl != 600 {
			t.Fatalf("expected the SOA with TTL min(TTL, MINIMUM)=600 (RFC 2308 §3), got %v", soas)
		}
		f.verifyAllSigs(t, resp.Ns)
		f.provesAbsent(t, resp.Ns, "nope.example.org.")
		f.provesAbsent(t, resp.Ns, "*.example.org.")
		if f.nsec3 {
			f.matchBitmap(t, resp.Ns, "example.org.") // closest encloser
		}
		for _, rr := range resp.Ns {
			if t2 := rr.Header().Rrtype; (t2 == dns.TypeNSEC || t2 == dns.TypeNSEC3) && rr.Header().Ttl != 600 {
				t.Fatalf("denial records must have TTL min(SOA TTL, MINIMUM) (RFC 9077): %v", rr)
			}
		}
	})
}

func TestLookupEmptyNonTerminalIsNODATA(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		for _, name := range []string{"deep.example.org.", "b.deep.example.org."} {
			resp := queryDO(t, f.addr, name, dns.TypeA)
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
				t.Fatalf("%s: an empty non-terminal exists (RFC 4592 §2.2.2), got %v", name, resp)
			}
			f.verifyAllSigs(t, resp.Ns)
			if f.nsec3 {
				if bm := f.matchBitmap(t, resp.Ns, name); len(bm) != 0 {
					t.Fatalf("%s: an empty non-terminal's NSEC3 has an empty bitmap (RFC 5155 §7.1), got %v", name, bm)
				}
			} else {
				f.provesAbsent(t, resp.Ns, name)
			}
		}
	})
}

func TestLookupUnsignedDelegation(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "host.sub.example.org.", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || resp.Authoritative || len(resp.Answer) != 0 {
			t.Fatalf("expected a referral (RFC 1034 §4.3.2), got %v", resp)
		}
		if ns := records[*dns.NS](resp.Ns); len(ns) != 1 || ns[0].Hdr.Name != "sub.example.org." {
			t.Fatalf("expected the delegation NS, got %v", resp.Ns)
		}
		for _, sig := range records[*dns.RRSIG](resp.Ns) {
			if sig.TypeCovered == dns.TypeNS {
				t.Fatalf("delegation NS must not be signed (RFC 4035 §2.2)")
			}
		}
		if glue := records[*dns.A](resp.Extra); len(glue) != 1 || glue[0].Hdr.Name != "ns.sub.example.org." {
			t.Fatalf("expected the glue, got %v", resp.Extra)
		}
		bm := f.matchBitmap(t, resp.Ns, "sub.example.org.")
		if !hasType(bm, dns.TypeNS) || hasType(bm, dns.TypeDS) {
			t.Fatalf("expected proof of no DS at the cut (RFC 4035 §3.1.4.1), bitmap %v", bm)
		}
		if f.nsec3 && hasType(bm, dns.TypeRRSIG) {
			t.Fatalf("an unsigned delegation has no RRSIG at its name, bitmap %v", bm)
		}
		f.verifyAllSigs(t, resp.Ns)

		z, _ := f.s.Store.Get("example.org.")
		if len(z.LookupRRSIG("ns.sub.example.org.", dns.TypeA)) != 0 || len(z.LookupRRSIG("sub.example.org.", dns.TypeNS)) != 0 {
			t.Fatalf("glue and delegation NS must be stored unsigned")
		}
		if !f.nsec3 && len(z.Lookup("ns.sub.example.org.", dns.TypeNSEC)) != 0 {
			t.Fatalf("glue must not be in the NSEC chain (RFC 4035 §2.3)")
		}
	})
}

func TestLookupSignedDelegation(t *testing.T) {
	forBothChains(t, func(t *testing.T, f *lookupFixture) {
		resp := queryDO(t, f.addr, "www.sec.example.org.", dns.TypeA)
		if resp.Authoritative || len(records[*dns.DS](resp.Ns)) != 1 {
			t.Fatalf("expected a referral with the DS, got %v", resp)
		}
		f.verifyAllSigs(t, resp.Ns)

		ds := queryDO(t, f.addr, "sec.example.org.", dns.TypeDS)
		if !ds.Authoritative || len(records[*dns.DS](ds.Answer)) != 1 || len(records[*dns.RRSIG](ds.Answer)) != 1 {
			t.Fatalf("the DS at a cut is the parent's authoritative data (RFC 4035 §3.1.4.1), got %v", ds)
		}
		f.verifyAllSigs(t, ds.Answer)
	})
}

// TestLookupDSAnsweredFromParentWhenBothHosted: with the child zone also
// hosted here, DS at its apex still comes from the parent.
func TestLookupDSAnsweredFromParentWhenBothHosted(t *testing.T) {
	f := newLookupFixture(t, false)
	childKey, childPriv, err := GenerateEd25519Key("sec.example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: "sec.example.org.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns.example.net.", Mbox: "hostmaster.sec.example.org.", Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300,
	}
	www := &dns.A{Hdr: dns.RR_Header{Name: "www.sec.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.9")}
	m, err := BuildFullZonePush("sec.example.org.", soa, []dns.RR{www}, childKey, childPriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	wire, err := SignUpdate(m, childKey, ed25519.PrivateKey(childPriv), now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if resp := sendRaw(t, f.addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("child onboarding rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	ds := queryDO(t, f.addr, "sec.example.org.", dns.TypeDS)
	if len(records[*dns.DS](ds.Answer)) != 1 {
		t.Fatalf("expected the parent's DS, got %v", ds)
	}
	f.verifyAllSigs(t, ds.Answer)
	if a := query(t, f.addr, "www.sec.example.org.", dns.TypeA); !a.Authoritative || len(a.Answer) != 1 {
		t.Fatalf("expected the child's own answer, got %v", a)
	}
}

// TestLookupTruncatesOverUDP: an answer too large for the client's UDP
// buffer comes back truncated (RFC 1035 §4.2.1, RFC 6891 §6.2.5).
func TestLookupTruncatesOverUDP(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	var rrs []dns.RR
	for i := 0; i < 60; i++ {
		rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{Name: "big.example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, byte(i))})
	}
	m, err := BuildFullZonePush("example.org.", testSOA(1), rrs, key, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp := sendRaw(t, addr, signNow(t, m, key, priv)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if resp := query(t, addr, "big.example.org.", dns.TypeA); !resp.Truncated {
		t.Fatalf("expected TC over plain UDP, got %d records", len(resp.Answer))
	}
}

// TestContentPushBreakingZoneRulesIsRefused: a push can be perfectly
// signed and still not be a valid zone.
func TestContentPushBreakingZoneRulesIsRefused(t *testing.T) {
	rr := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := map[string][]dns.RR{
		"CNAME and other data": {rr("a.example.org. 300 IN CNAME b.example.org."), rr("a.example.org. 300 IN TXT x")},
		"RRset TTL mismatch":   {rr("a.example.org. 300 IN A 192.0.2.1"), rr("a.example.org. 600 IN A 192.0.2.2")},
		"name below a DNAME":   {rr("d.example.org. 300 IN DNAME example.net."), rr("x.d.example.org. 300 IN A 192.0.2.1")},
	}
	for name, rrs := range cases {
		t.Run(name, func(t *testing.T) {
			s := newTestSazu("example.org.")
			addr := serveThroughRealServer(t, s)
			key, priv, err := GenerateEd25519Key("example.org.", true)
			if err != nil {
				t.Fatal(err)
			}
			m, err := BuildFullZonePush("example.org.", testSOA(1), rrs, key, priv, nil)
			if err != nil {
				t.Fatal(err)
			}
			expectRefusedWith(t, name, sendRaw(t, addr, signNow(t, m, key, priv)), dns.RcodeRefused, statusErrInvalidZoneContent)
		})
	}
}
