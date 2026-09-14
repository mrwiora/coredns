package sazu

import (
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// nsecStateFor builds a ChainState the way a client's local cache would
// hold it, from a fresh chain over adds -- mirroring exactly what a full
// push (push-zone) would have last confirmed.
func nsecStateFor(soa *dns.SOA, adds []dns.RR) *ChainState {
	state := &ChainState{Scheme: "nsec", Apex: soa.Hdr.Name, Minttl: soa.Minttl, Records: map[string]dns.RR{}}
	for _, rr := range BuildNSECChain(soa, adds) {
		if n, ok := rr.(*dns.NSEC); ok {
			state.Records[strings.ToLower(n.Hdr.Name)] = n
		}
	}
	return state
}

func nsec3StateFor(soa *dns.SOA, adds []dns.RR, opts NSEC3Options) *ChainState {
	chain := BuildNSEC3Chain(soa, adds, opts)
	var param *dns.NSEC3PARAM
	byHash := map[string]dns.RR{}
	for _, rr := range chain {
		switch v := rr.(type) {
		case *dns.NSEC3:
			byHash[strings.ToLower(v.Hdr.Name)] = v
		case *dns.NSEC3PARAM:
			param = v
		}
	}
	state := &ChainState{Scheme: "nsec3", Param: param, Apex: soa.Hdr.Name, Minttl: soa.Minttl, Records: map[string]dns.RR{}}
	// Recover the real-name keys the same way ComputeChainPatch would --
	// by hashing every candidate name and matching.
	names := map[string]bool{strings.ToLower(soa.Hdr.Name): true}
	for _, rr := range adds {
		names[strings.ToLower(dns.Fqdn(rr.Header().Name))] = true
	}
	for name := range names {
		owner := NSEC3Hash(name, param) + "." + strings.ToLower(soa.Hdr.Name)
		if rr, ok := byHash[owner]; ok {
			state.Records[name] = rr
		}
	}
	return state
}

// walkNSECRing follows a fully-patched Records map (state.Records with
// patch.Adds applied and patch.Deletes removed) from the apex all the
// way around, failing the test if it doesn't visit every expected name
// exactly once and cycle back to the start -- the same invariant
// BuildNSECChain's own tests check, here re-checked after an incremental
// edit rather than a from-scratch build.
func walkNSECRing(t *testing.T, records map[string]dns.RR, apex string, want []string) {
	t.Helper()
	visited := map[string]bool{}
	name := strings.ToLower(apex)
	for i := 0; i < len(records)+1; i++ {
		if visited[name] {
			break
		}
		visited[name] = true
		rec, ok := records[name]
		if !ok {
			t.Fatalf("ring points at %s, which has no record", name)
		}
		name = strings.ToLower(rec.(*dns.NSEC).NextDomain)
	}
	if name != strings.ToLower(apex) {
		t.Fatalf("ring did not cycle back to the apex, ended at %s", name)
	}
	var got []string
	for n := range visited {
		got = append(got, n)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("ring visited %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ring visited %v, want %v", got, want)
		}
	}
}

// applyPatch returns a copy of records with patch's adds/deletes applied
// -- what the server's own insertLocked/DeleteRRset logic would produce.
func applyPatch(records map[string]dns.RR, patch *ChainPatch) map[string]dns.RR {
	out := make(map[string]dns.RR, len(records))
	for k, v := range records {
		out[k] = v
	}
	for _, rr := range patch.Adds {
		out[strings.ToLower(rr.Header().Name)] = rr
	}
	for _, rr := range patch.Deletes {
		delete(out, strings.ToLower(rr.Header().Name))
	}
	return out
}

func TestComputeChainPatchInsertsNewNameNSEC(t *testing.T) {
	soa := testSOA(1)
	state := nsecStateFor(soa, []dns.RR{soa, testA("www.example.org.", net.IPv4(203, 0, 113, 10))})

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "mail.example.org.", Type: dns.TypeA, Add: true}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Deletes) != 0 {
		t.Fatalf("expected no deletes for a pure insertion, got %+v", patch.Deletes)
	}
	if len(patch.Adds) != 2 {
		t.Fatalf("expected 2 adds (new record + patched predecessor), got %d: %+v", len(patch.Adds), patch.Adds)
	}
	if len(patch.Prerequisites) != 1 {
		t.Fatalf("expected exactly 1 prerequisite (the predecessor's prior value), got %d: %+v", len(patch.Prerequisites), patch.Prerequisites)
	}

	prereq := patch.Prerequisites[0]
	old, ok := state.Records[strings.ToLower(prereq.Header().Name)]
	if !ok || !rrEqualContent(old, prereq) {
		t.Fatalf("expected the prerequisite to assert the predecessor's exact prior value, got %+v (prior: %+v)", prereq, old)
	}

	after := applyPatch(state.Records, patch)
	walkNSECRing(t, after, "example.org.", []string{"example.org.", "www.example.org.", "mail.example.org."})
}

func TestComputeChainPatchRemovesNameNSEC(t *testing.T) {
	soa := testSOA(1)
	state := nsecStateFor(soa, []dns.RR{
		soa,
		testA("www.example.org.", net.IPv4(203, 0, 113, 10)),
		testA("mail.example.org.", net.IPv4(203, 0, 113, 20)),
	})

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "mail.example.org.", Type: dns.TypeA, Add: false}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 1 {
		t.Fatalf("expected exactly 1 add (patched predecessor), got %d: %+v", len(patch.Adds), patch.Adds)
	}
	if len(patch.Deletes) != 1 || !strings.EqualFold(patch.Deletes[0].Header().Name, "mail.example.org.") {
		t.Fatalf("expected exactly 1 delete, for mail.example.org., got %+v", patch.Deletes)
	}
	if len(patch.Prerequisites) != 2 {
		t.Fatalf("expected 2 prerequisites (predecessor + the removed name itself), got %d: %+v", len(patch.Prerequisites), patch.Prerequisites)
	}

	after := applyPatch(state.Records, patch)
	walkNSECRing(t, after, "example.org.", []string{"example.org.", "www.example.org."})
}

func TestComputeChainPatchBitmapOnlyEditDoesNotChangeTopologyNSEC(t *testing.T) {
	soa := testSOA(1)
	state := nsecStateFor(soa, []dns.RR{soa, testA("www.example.org.", net.IPv4(203, 0, 113, 10))})
	before := state.Records["www.example.org."].(*dns.NSEC).NextDomain

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "www.example.org.", Type: dns.TypeTXT, Add: true}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 1 || len(patch.Deletes) != 0 || len(patch.Prerequisites) != 1 {
		t.Fatalf("expected exactly 1 add, 0 deletes, 1 prerequisite for a bitmap-only edit, got adds=%+v deletes=%+v prereqs=%+v",
			patch.Adds, patch.Deletes, patch.Prerequisites)
	}
	patched := patch.Adds[0].(*dns.NSEC)
	if !strings.EqualFold(patched.Hdr.Name, "www.example.org.") {
		t.Fatalf("expected the patched record to still be at www.example.org., got %s", patched.Hdr.Name)
	}
	if patched.NextDomain != before {
		t.Fatalf("expected NextDomain to stay %s (no topology change), got %s", before, patched.NextDomain)
	}
	assertSortedTypesEqual(t, patched.TypeBitMap, []uint16{dns.TypeA, dns.TypeTXT, dns.TypeNSEC, dns.TypeRRSIG})
}

// fiveNameZoneState builds a zone with five ordinary names (plus the
// apex) whose canonical order is unambiguous -- a.example.org. through
// e.example.org. -- so a test touching "c" is genuinely touching an
// interior node with two other ordinary domains as neighbors, not the
// apex on one side the way a smaller zone's tests unavoidably do.
func fiveNameZoneState(soa *dns.SOA) *ChainState {
	return nsecStateFor(soa, []dns.RR{
		soa,
		testA("a.example.org.", net.IPv4(203, 0, 113, 1)),
		testA("b.example.org.", net.IPv4(203, 0, 113, 2)),
		testA("c.example.org.", net.IPv4(203, 0, 113, 3)),
		testA("d.example.org.", net.IPv4(203, 0, 113, 4)),
		testA("e.example.org.", net.IPv4(203, 0, 113, 5)),
	})
}

// TestComputeChainPatchUpdatesInteriorNameNSEC proves an update to a
// domain in the middle of a longer chain -- both its predecessor ("b")
// and successor ("d") are ordinary domains, not the apex, unlike every
// other edit test in this file -- patches only that one record and
// leaves both neighbors completely untouched.
func TestComputeChainPatchUpdatesInteriorNameNSEC(t *testing.T) {
	soa := testSOA(1)
	state := fiveNameZoneState(soa)
	beforeC := state.Records["c.example.org."].(*dns.NSEC)
	beforeB := state.Records["b.example.org."]
	beforeD := state.Records["d.example.org."]
	if beforeC.NextDomain != "d.example.org." {
		t.Fatalf("test setup: expected c's successor to be d, got %s", beforeC.NextDomain)
	}

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "c.example.org.", Type: dns.TypeTXT, Add: true}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 1 || len(patch.Deletes) != 0 || len(patch.Prerequisites) != 1 {
		t.Fatalf("expected exactly 1 add, 0 deletes, 1 prerequisite, got adds=%+v deletes=%+v prereqs=%+v",
			patch.Adds, patch.Deletes, patch.Prerequisites)
	}
	patched := patch.Adds[0].(*dns.NSEC)
	if !strings.EqualFold(patched.Hdr.Name, "c.example.org.") {
		t.Fatalf("expected the patched record to still be at c.example.org., got %s", patched.Hdr.Name)
	}
	if patched.NextDomain != "d.example.org." {
		t.Fatalf("expected NextDomain to stay d.example.org. (no topology change), got %s", patched.NextDomain)
	}
	assertSortedTypesEqual(t, patched.TypeBitMap, []uint16{dns.TypeA, dns.TypeTXT, dns.TypeNSEC, dns.TypeRRSIG})

	after := applyPatch(state.Records, patch)
	if !rrEqualContent(after["b.example.org."], beforeB) {
		t.Fatalf("expected b (c's predecessor) to be untouched, got %+v (was %+v)", after["b.example.org."], beforeB)
	}
	if !rrEqualContent(after["d.example.org."], beforeD) {
		t.Fatalf("expected d (c's successor) to be untouched, got %+v (was %+v)", after["d.example.org."], beforeD)
	}
	walkNSECRing(t, after, "example.org.", []string{
		"example.org.", "a.example.org.", "b.example.org.", "c.example.org.", "d.example.org.", "e.example.org.",
	})
}

// TestComputeChainPatchRemovesInteriorNameNSEC is the same setup for a
// full removal: "c" is removed entirely, its predecessor "b" is patched
// to skip straight to "d" (c's old successor), and "d" itself -- despite
// being the node c's removal logically "points past" -- is never touched
// at all, since removing c only changes who points AT d, not d's own
// record.
func TestComputeChainPatchRemovesInteriorNameNSEC(t *testing.T) {
	soa := testSOA(1)
	state := fiveNameZoneState(soa)
	beforeD := state.Records["d.example.org."]

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "c.example.org.", Type: dns.TypeA, Add: false}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 1 {
		t.Fatalf("expected exactly 1 add (patched predecessor b), got %d: %+v", len(patch.Adds), patch.Adds)
	}
	patchedB := patch.Adds[0].(*dns.NSEC)
	if !strings.EqualFold(patchedB.Hdr.Name, "b.example.org.") {
		t.Fatalf("expected the patched record to be b.example.org. (c's predecessor), got %s", patchedB.Hdr.Name)
	}
	if patchedB.NextDomain != "d.example.org." {
		t.Fatalf("expected b's NextDomain to skip straight to d.example.org., got %s", patchedB.NextDomain)
	}
	if len(patch.Deletes) != 1 || !strings.EqualFold(patch.Deletes[0].Header().Name, "c.example.org.") {
		t.Fatalf("expected exactly 1 delete, for c.example.org., got %+v", patch.Deletes)
	}
	if len(patch.Prerequisites) != 2 {
		t.Fatalf("expected 2 prerequisites (b + the removed c itself), got %d: %+v", len(patch.Prerequisites), patch.Prerequisites)
	}
	for _, rr := range patch.Adds {
		if strings.EqualFold(rr.Header().Name, "d.example.org.") {
			t.Fatalf("expected d (c's successor) to never be touched by removing c, got %+v", rr)
		}
	}

	after := applyPatch(state.Records, patch)
	if !rrEqualContent(after["d.example.org."], beforeD) {
		t.Fatalf("expected d to be completely unchanged, got %+v (was %+v)", after["d.example.org."], beforeD)
	}
	walkNSECRing(t, after, "example.org.", []string{
		"example.org.", "a.example.org.", "b.example.org.", "d.example.org.", "e.example.org.",
	})
}

func TestComputeChainPatchNoOpWhenTypeAlreadyPresent(t *testing.T) {
	soa := testSOA(1)
	state := nsecStateFor(soa, []dns.RR{soa, testA("www.example.org.", net.IPv4(203, 0, 113, 10))})

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "www.example.org.", Type: dns.TypeA, Add: true}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 0 || len(patch.Deletes) != 0 || len(patch.Prerequisites) != 0 {
		t.Fatalf("expected a total no-op, got adds=%+v deletes=%+v prereqs=%+v", patch.Adds, patch.Deletes, patch.Prerequisites)
	}
}

// TestComputeChainPatchTwoInsertsIntoTheSameGapNSEC proves the
// reuse-the-full-builder-then-diff approach handles two new names
// landing in the same canonical-order gap in a single push correctly --
// the case a hand-rolled split-one-edge-at-a-time implementation would
// need its own separate logic to get right.
func TestComputeChainPatchTwoInsertsIntoTheSameGapNSEC(t *testing.T) {
	soa := testSOA(1)
	// "a." and "z." sort on either side of the alphabet -- "m1"/"m2" both
	// land in the single gap between them.
	state := nsecStateFor(soa, []dns.RR{
		soa,
		testA("a.example.org.", net.IPv4(203, 0, 113, 1)),
		testA("z.example.org.", net.IPv4(203, 0, 113, 2)),
	})

	patch, err := ComputeChainPatch(state, []ChainOp{
		{Name: "m1.example.org.", Type: dns.TypeA, Add: true},
		{Name: "m2.example.org.", Type: dns.TypeA, Add: true},
	})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	after := applyPatch(state.Records, patch)
	walkNSECRing(t, after, "example.org.", []string{
		"example.org.", "a.example.org.", "m1.example.org.", "m2.example.org.", "z.example.org.",
	})
}

func TestComputeChainPatchInsertsNewNameNSEC3(t *testing.T) {
	soa := testSOA(1)
	state := nsec3StateFor(soa, []dns.RR{soa, testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, NSEC3Options{})

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "mail.example.org.", Type: dns.TypeA, Add: true}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 2 || len(patch.Deletes) != 0 || len(patch.Prerequisites) != 1 {
		t.Fatalf("expected 2 adds, 0 deletes, 1 prerequisite, got adds=%+v deletes=%+v prereqs=%+v",
			patch.Adds, patch.Deletes, patch.Prerequisites)
	}
	for _, rr := range patch.Adds {
		if _, ok := rr.(*dns.NSEC3); !ok {
			t.Fatalf("expected NSEC3 records in Adds, got %+v", rr)
		}
	}
}

func TestComputeChainPatchRemovesNameNSEC3(t *testing.T) {
	soa := testSOA(1)
	state := nsec3StateFor(soa, []dns.RR{
		soa,
		testA("www.example.org.", net.IPv4(203, 0, 113, 10)),
		testA("mail.example.org.", net.IPv4(203, 0, 113, 20)),
	}, NSEC3Options{})

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "mail.example.org.", Type: dns.TypeA, Add: false}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Deletes) != 1 {
		t.Fatalf("expected exactly 1 delete, got %+v", patch.Deletes)
	}
	if len(patch.Prerequisites) != 2 {
		t.Fatalf("expected 2 prerequisites, got %+v", patch.Prerequisites)
	}
}

func TestComputeChainPatchErrors(t *testing.T) {
	if _, err := ComputeChainPatch(&ChainState{Scheme: "nsec"}, nil); err == nil {
		t.Fatalf("expected an error for a missing apex")
	}
	if _, err := ComputeChainPatch(&ChainState{Apex: "example.org.", Scheme: "bogus"}, nil); err == nil {
		t.Fatalf("expected an error for an unknown scheme")
	}
	if _, err := ComputeChainPatch(&ChainState{Apex: "example.org.", Scheme: "nsec3"}, nil); err == nil {
		t.Fatalf("expected an error for nsec3 with no NSEC3PARAM")
	}

	soa := testSOA(1)
	state := nsecStateFor(soa, []dns.RR{soa})
	if _, err := ComputeChainPatch(state, []ChainOp{{Name: "example.org.", Type: dns.TypeSOA, Add: false}}); err == nil {
		t.Fatalf("expected an error for removing the zone apex's last content type")
	}
}

// TestServerAcceptsIncrementalChainPatchWithoutPurging is the end-to-end
// proof of this whole mechanism: a partial push carrying a
// ComputeChainPatch-produced NSEC3 patch, plus its RFC 2136 §2.4.2
// prerequisites, is applied directly -- PurgeNSEC is never invoked (see
// handler.go's containsChainRecords/isFullPush), so the chain from
// before the partial push and the two new records it adds coexist
// correctly, rather than the whole chain vanishing until the next full
// push the way it would without this mechanism.
func TestServerAcceptsIncrementalChainPatchWithoutPurging(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	key, priv := onboardExampleOrgNSEC3(t, addr, NSEC3Options{})

	soa := testSOA(1)
	state := nsec3StateFor(soa, []dns.RR{soa, key, testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, NSEC3Options{})

	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "mail.example.org.", Type: dns.TypeA, Add: true}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}

	content := append([]dns.RR{testA("mail.example.org.", net.IPv4(203, 0, 113, 20))}, patch.Adds...)
	now := time.Now()
	signed, err := SignZoneContent(content, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing partial push content: %v", err)
	}

	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Used(patch.Prerequisites)
	m.Insert(signed)
	wire, err := SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing transaction: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("partial push with chain patch rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if answer := queryDO(t, addr, "mail.example.org.", dns.TypeA); len(answer.Answer) != 2 { // A + its RRSIG (DO bit set)
		t.Fatalf("expected mail.example.org. to now be servable, got %+v", answer.Answer)
	}

	// The chain must still be intact and cover every name, old and new --
	// not purged, not broken.
	resp := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	n3s, sigs := splitNSEC3AndRRSIGs(resp.Ns)
	if len(n3s) == 0 {
		t.Fatalf("expected the chain to still produce an NSEC3 proof after an incremental patch, got %+v", resp.Ns)
	}
	for _, n := range n3s {
		sig, ok := sigs[strings.ToLower(n.Hdr.Name)]
		if !ok {
			t.Fatalf("NSEC3 at %s has no covering RRSIG", n.Hdr.Name)
		}
		if err := sig.Verify(key, []dns.RR{n}); err != nil {
			t.Fatalf("NSEC3 at %s's RRSIG does not verify: %v", n.Hdr.Name, err)
		}
	}
}

// TestServerRejectsStaleChainPatchAndReturnsCurrentValue proves the
// other half: a partial push whose chain-patch prerequisite no longer
// matches the server's actual current record (the client's local cache
// has drifted) is rejected outright -- nothing is partially applied --
// with statusErrStaleChain and the zone's real current record attached,
// so the client can reconcile.
func TestServerRejectsStaleChainPatchAndReturnsCurrentValue(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	key, priv := onboardExampleOrgNSEC3(t, addr, NSEC3Options{})

	soa := testSOA(1)
	param := testNSEC3Param(0, "")
	wwwOwner := NSEC3Hash("www.example.org.", param) + ".example.org."

	// A prerequisite asserting a NextDomain the predecessor (www, in a
	// two-name zone) does NOT actually have -- simulating a client whose
	// local cache is stale.
	staleAssumed := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: wwwOwner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: soa.Minttl},
		Hash:       dns.SHA1,
		Iterations: 0,
		HashLength: 20,
		NextDomain: NSEC3Hash("this-was-never-pushed.example.org.", param),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}

	now := time.Now()
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Used([]dns.RR{staleAssumed})
	wire, err := SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	resp := sendRaw(t, addr, wire)
	if resp.Rcode != dns.RcodeNXRrset {
		t.Fatalf("rcode = %s, want NXRRSET (stale prerequisite)", dns.RcodeToString[resp.Rcode])
	}
	var sawStatus bool
	var actual *dns.NSEC3
	for _, rr := range resp.Extra {
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 && txt.Txt[0] == "ERR_STALE_CHAIN" {
			sawStatus = true
		}
		if n, ok := rr.(*dns.NSEC3); ok {
			actual = n
		}
	}
	if !sawStatus {
		t.Fatalf("expected an ERR_STALE_CHAIN diagnostic, got %+v", resp.Extra)
	}
	if actual == nil {
		t.Fatalf("expected the zone's actual current NSEC3 record attached, got %+v", resp.Extra)
	}
	if actual.NextDomain == staleAssumed.NextDomain {
		t.Fatalf("expected the returned record to differ from the stale assumed one")
	}

	// Nothing was applied: mail.example.org. (never pushed) still doesn't
	// resolve, proving the whole update was rejected, not partially
	// applied.
	if answer := queryDO(t, addr, "mail.example.org.", dns.TypeA); len(answer.Answer) != 0 {
		t.Fatalf("expected no content to have been applied, got %+v", answer.Answer)
	}
}

// TestKSKRolloverDoesNotPurgeExistingChain is a regression test for a
// real bug this feature's own testing found (not something it
// introduced, but something this level of chain-state checking was the
// first thing to ever notice): a KSK rollover carries an apex DNSKEY,
// same as a full push does, so classifying "should the chain be purged"
// by that signal alone (isFullPush) purged the chain on every single
// key rotation, even though a rollover changes no served content
// whatsoever and supplies no replacement chain. See handler.go's
// PurgeNSEC call site for the fix (containsAPEXSOA, not isFullPush,
// decides "full push" for purge purposes) and changesChainRelevantContent.
func TestKSKRolloverDoesNotPurgeExistingChain(t *testing.T) {
	s := newTestSazu("example.org.")
	s.InsecureSkipChainValidation = false
	s.Validator = fakeValidator{err: nil}
	addr := serveThroughRealServer(t, s)

	oldKey, oldPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating old key: %v", err)
	}
	push, err := BuildFullZonePushNSEC3("example.org.", testSOA(1), []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}, oldKey, oldPriv, nil, NSEC3Options{})
	if err != nil {
		t.Fatalf("building onboarding push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(push, oldKey, oldPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing onboarding push: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	before := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if n3s, _ := splitNSEC3AndRRSIGs(before.Ns); len(n3s) == 0 {
		t.Fatalf("expected a usable NSEC3 chain right after onboarding, got none")
	}

	newKey, newPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating new key: %v", err)
	}
	rollover := new(dns.Msg)
	rollover.SetQuestion("example.org.", dns.TypeSOA)
	rollover.Opcode = dns.OpcodeUpdate
	rollover.Insert([]dns.RR{
		&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: newKey.Flags, Protocol: newKey.Protocol, Algorithm: newKey.Algorithm, PublicKey: newKey.PublicKey},
	})
	now = time.Now()
	rolloverWire, err := SignUpdate(rollover, newKey, newPriv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing rollover: %v", err)
	}
	if resp := sendRaw(t, addr, rolloverWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rollover rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	after := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	n3s, sigs := splitNSEC3AndRRSIGs(after.Ns)
	if len(n3s) == 0 {
		t.Fatalf("expected the chain to survive a KSK rollover untouched, got none")
	}
	// A mere rollover never re-signs existing content -- only the new
	// DNSKEY is added -- so the untouched chain's RRSIGs are still the
	// ORIGINAL ones, from the key that's since been superseded for
	// transaction authentication. That's fine: it's the exact same
	// signature a validating resolver already saw and accepted before
	// the rollover, on content that hasn't changed.
	for _, n := range n3s {
		sig, ok := sigs[strings.ToLower(n.Hdr.Name)]
		if !ok {
			t.Fatalf("NSEC3 at %s has no covering RRSIG after rollover", n.Hdr.Name)
		}
		if err := sig.Verify(oldKey, []dns.RR{n}); err != nil {
			t.Fatalf("NSEC3 at %s's original RRSIG no longer verifies after rollover: %v", n.Hdr.Name, err)
		}
	}
}

// TestServerRemovesInteriorDomainViaIncrementalPatch is the real,
// end-to-end version of TestComputeChainPatchRemovesInteriorNameNSEC:
// a five-domain zone, pushed and served for real, has one interior
// domain ("c", with two ordinary domains as neighbors, not the apex)
// removed via an actual partial push carrying an incremental chain
// patch -- proving the removed name stops resolving, both of its former
// neighbors keep resolving exactly as before, and the chain still
// produces a valid, fully-linked NSEC3 proof over the four domains that
// remain.
func TestServerRemovesInteriorDomainViaIncrementalPatch(t *testing.T) {
	s := newTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	rrs := []dns.RR{
		testA("a.example.org.", net.IPv4(203, 0, 113, 1)),
		testA("b.example.org.", net.IPv4(203, 0, 113, 2)),
		testA("c.example.org.", net.IPv4(203, 0, 113, 3)),
		testA("d.example.org.", net.IPv4(203, 0, 113, 4)),
		testA("e.example.org.", net.IPv4(203, 0, 113, 5)),
	}
	onboard, err := BuildFullZonePushNSEC3("example.org.", soa, rrs, key, priv, nil, NSEC3Options{})
	if err != nil {
		t.Fatalf("building onboarding push: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(onboard, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing onboarding push: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	state := nsec3StateFor(soa, append([]dns.RR{soa, key}, rrs...), NSEC3Options{})
	patch, err := ComputeChainPatch(state, []ChainOp{{Name: "c.example.org.", Type: dns.TypeA, Add: false}})
	if err != nil {
		t.Fatalf("ComputeChainPatch: %v", err)
	}
	if len(patch.Adds) != 1 || len(patch.Deletes) != 1 {
		t.Fatalf("expected exactly 1 patched neighbor and 1 delete, got adds=%+v deletes=%+v", patch.Adds, patch.Deletes)
	}
	signed, err := SignZoneContent(patch.Adds, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing chain patch: %v", err)
	}

	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Used(patch.Prerequisites)
	m.Insert(signed)
	// RFC 2136 §2.5.3 "delete all RRsets from a name" -- not
	// RemoveRRset(A), which would leave c's now-orphaned RRSIG(A)
	// behind and make c.example.org. still "exist" (NODATA rather than
	// NXDOMAIN): removing a name's real content needs to take every
	// RRset there with it, chain record aside (that one lives under a
	// completely different owner key -- the hash -- and is removed
	// separately, just below).
	m.RemoveName([]dns.RR{testA("c.example.org.", nil)})
	m.RemoveRRset(patch.Deletes) // remove c's own chain record
	wire, err = SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing transaction: %v", err)
	}
	if resp := sendRaw(t, addr, wire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("removal push rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	if resp := queryDO(t, addr, "c.example.org.", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("c.example.org. rcode = %s, want NXDOMAIN (removed)", dns.RcodeToString[resp.Rcode])
	}
	for _, name := range []string{"a.example.org.", "b.example.org.", "d.example.org.", "e.example.org."} {
		if answer := queryDO(t, addr, name, dns.TypeA); len(answer.Answer) != 2 { // A + RRSIG
			t.Fatalf("expected %s to still resolve untouched, got %+v", name, answer.Answer)
		}
	}

	resp := queryDO(t, addr, "does-not-exist.example.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	n3s, sigs := splitNSEC3AndRRSIGs(resp.Ns)
	if len(n3s) == 0 {
		t.Fatalf("expected the chain to still produce an NSEC3 proof after removing an interior domain, got %+v", resp.Ns)
	}
	for _, n := range n3s {
		sig, ok := sigs[strings.ToLower(n.Hdr.Name)]
		if !ok {
			t.Fatalf("NSEC3 at %s has no covering RRSIG", n.Hdr.Name)
		}
		if err := sig.Verify(key, []dns.RR{n}); err != nil {
			t.Fatalf("NSEC3 at %s's RRSIG does not verify: %v", n.Hdr.Name, err)
		}
	}
}
