package sazu

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testZoneFile = `$ORIGIN example.org.
@   3600 IN SOA ns1.example.org. hostmaster.example.org. 2024010100 3600 900 604800 3600
@   3600 IN NS  ns1.example.org.
www 300  IN A   203.0.113.10
mx  300  IN A   203.0.113.11
@   3600 IN MX  10 mx.example.org.
`

func writeTestZone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "example.org.zone")
	if err := os.WriteFile(path, []byte(testZoneFile), 0o600); err != nil {
		t.Fatalf("writing test zone file: %v", err)
	}
	return path
}

func TestLoadZoneFileSeparatesSOAFromOtherRecords(t *testing.T) {
	path := writeTestZone(t)
	soa, rrs, err := LoadZoneFile(path, "example.org.")
	if err != nil {
		t.Fatalf("LoadZoneFile: %v", err)
	}
	if soa.Serial != 2024010100 {
		t.Fatalf("got serial %d, want 2024010100", soa.Serial)
	}
	if len(rrs) != 4 { // NS, www A, mx A, MX -- SOA excluded
		t.Fatalf("got %d non-SOA records, want 4", len(rrs))
	}
	for _, rr := range rrs {
		if _, isSOA := rr.(*dns.SOA); isSOA {
			t.Fatalf("SOA record leaked into the non-SOA record list")
		}
	}
}

func TestLoadZoneFileRejectsMissingSOA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-soa.zone")
	if err := os.WriteFile(path, []byte("$ORIGIN example.org.\nwww 300 IN A 203.0.113.10\n"), 0o600); err != nil {
		t.Fatalf("writing zone file: %v", err)
	}
	if _, _, err := LoadZoneFile(path, "example.org."); err == nil {
		t.Fatalf("expected an error for a zone file with no SOA record")
	}
}

func TestBuildFullZonePushShapesPrerequisiteAndUpdateSections(t *testing.T) {
	path := writeTestZone(t)
	soa, rrs, err := LoadZoneFile(path, "example.org.")
	if err != nil {
		t.Fatalf("LoadZoneFile: %v", err)
	}
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	previousSOA := *soa
	previousSOA.Serial-- // simulate "what the client last saw published"
	m, err := BuildFullZonePush("example.org.", soa, rrs, key, priv, &previousSOA)
	if err != nil {
		t.Fatalf("BuildFullZonePush: %v", err)
	}

	if m.Opcode != dns.OpcodeUpdate {
		t.Fatalf("got opcode %d, want Update", m.Opcode)
	}
	if len(m.Question) != 1 || m.Question[0].Name != "example.org." {
		t.Fatalf("unexpected zone section: %+v", m.Question)
	}

	// Prerequisite section (Answer, per RFC 2136's field reuse): the
	// *previous* SOA, guarding against a stale push -- not the new one
	// being pushed.
	if len(m.Answer) != 1 {
		t.Fatalf("expected exactly one prerequisite, got %d", len(m.Answer))
	}
	gotSOA, ok := m.Answer[0].(*dns.SOA)
	if !ok || gotSOA.Serial != previousSOA.Serial {
		t.Fatalf("expected the SOA-serial staleness prerequisite against the previous serial, got %+v", m.Answer[0])
	}

	// Update section (Ns): the DNSKEY, the new SOA, every non-SOA record
	// from the zone file, a synthesized NSEC chain covering every distinct
	// owner name among those, and one RRSIG per distinct RRset among all
	// of it -- nothing dropped or duplicated, and everything actually
	// signed.
	var nonSigs []dns.RR
	var sigs []*dns.RRSIG
	var nsecs []*dns.NSEC
	for _, rr := range m.Ns {
		switch v := rr.(type) {
		case *dns.RRSIG:
			sigs = append(sigs, v)
		case *dns.NSEC:
			nsecs = append(nsecs, v)
			nonSigs = append(nonSigs, rr)
		default:
			nonSigs = append(nonSigs, rr)
		}
	}
	if len(nonSigs) != len(rrs)+2+len(nsecs) {
		t.Fatalf("got %d non-RRSIG update ops, want %d (%d zone records + DNSKEY + SOA + %d NSEC)",
			len(nonSigs), len(rrs)+2+len(nsecs), len(rrs), len(nsecs))
	}
	wantSigs := len(groupRRsets(nonSigs))
	if len(sigs) != wantSigs {
		t.Fatalf("got %d RRSIGs, want %d (one per distinct RRset)", len(sigs), wantSigs)
	}
	dnskeyRR, ok := nonSigs[0].(*dns.DNSKEY)
	if !ok || dnskeyRR.PublicKey != key.PublicKey {
		t.Fatalf("expected the candidate DNSKEY to be the first update op, got %+v", nonSigs[0])
	}
	newSOA, ok := nonSigs[1].(*dns.SOA)
	if !ok || newSOA.Serial != soa.Serial {
		t.Fatalf("expected the new SOA to be pushed as content (second update op), got %+v", nonSigs[1])
	}

	// The zone file's records land at 3 distinct owner names (the apex,
	// www, and mx), so the chain should have exactly 3 links, and
	// following NextDomain from any one of them should visit all 3 and
	// cycle back to the start (RFC 4034 §4: the chain is circular).
	if len(nsecs) != 3 {
		t.Fatalf("got %d NSEC records, want 3 (apex, www, mx)", len(nsecs))
	}
	byOwner := make(map[string]*dns.NSEC, len(nsecs))
	for _, n := range nsecs {
		byOwner[strings.ToLower(n.Hdr.Name)] = n
	}
	visited := map[string]bool{}
	name := strings.ToLower(nsecs[0].Hdr.Name)
	for i := 0; i < len(nsecs); i++ {
		if visited[name] {
			t.Fatalf("NSEC chain revisited %s before covering all %d owners", name, len(nsecs))
		}
		visited[name] = true
		next, ok := byOwner[name]
		if !ok {
			t.Fatalf("NSEC chain points at %s, which has no NSEC record of its own", name)
		}
		name = strings.ToLower(next.NextDomain)
	}
	if name != strings.ToLower(nsecs[0].Hdr.Name) {
		t.Fatalf("NSEC chain did not cycle back to its start, ended at %s", name)
	}

	for _, sig := range sigs {
		var rrset []dns.RR
		for _, rr := range nonSigs {
			if rr.Header().Rrtype == sig.TypeCovered && strings.EqualFold(rr.Header().Name, sig.Hdr.Name) {
				rrset = append(rrset, rr)
			}
		}
		if err := sig.Verify(dnskeyRR, rrset); err != nil {
			t.Fatalf("RRSIG covering %s/%s does not verify: %v", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], err)
		}
	}
}

func TestBuildFullZonePushFirstContactHasNoPrerequisite(t *testing.T) {
	path := writeTestZone(t)
	soa, rrs, err := LoadZoneFile(path, "example.org.")
	if err != nil {
		t.Fatalf("LoadZoneFile: %v", err)
	}
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	m, err := BuildFullZonePush("example.org.", soa, rrs, key, priv, nil)
	if err != nil {
		t.Fatalf("BuildFullZonePush: %v", err)
	}

	if len(m.Answer) != 0 {
		t.Fatalf("expected no prerequisites on a first-contact push, got %d", len(m.Answer))
	}
}

// TestBuildFullZonePushAcceptsHandBuiltRecords proves BuildFullZonePush
// itself has no dependency on the records having come from a real zone
// file -- any caller-constructed SOA/RRs work the same way. sazuctl's
// publish-zone command requires a zone file (LoadZoneFile) regardless;
// this only exercises the underlying library function.
func TestBuildFullZonePushAcceptsHandBuiltRecords(t *testing.T) {
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := synthesizeSOA("example.org.")
	ns := &dns.NS{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: soa.Ns}

	m, err := BuildFullZonePush("example.org.", soa, []dns.RR{ns}, key, priv, nil)
	if err != nil {
		t.Fatalf("BuildFullZonePush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	if err := VerifySIG0(wire, key); err != nil {
		t.Fatalf("a hand-built push should self-verify: %v", err)
	}
}

func TestBuildFullZonePushSignsAndVerifies(t *testing.T) {
	path := writeTestZone(t)
	soa, rrs, err := LoadZoneFile(path, "example.org.")
	if err != nil {
		t.Fatalf("LoadZoneFile: %v", err)
	}
	key, priv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	m, err := BuildFullZonePush("example.org.", soa, rrs, key, priv, nil)
	if err != nil {
		t.Fatalf("BuildFullZonePush: %v", err)
	}
	now := time.Now()
	wire, err := SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("signing full-zone push: %v", err)
	}
	if err := VerifySIG0(wire, key); err != nil {
		t.Fatalf("full-zone push should self-verify: %v", err)
	}
}

// dnskeysAndSigFromOps splits ops (an add-zsk/retire-zsk/KSK-rollover
// push's Ns section) into its added DNSKEY records, its deleted ones
// (RFC 2136 §2.5.4, class NONE), and its single RRSIG(DNSKEY) -- the
// three things TestBuildAddZSKPush.../TestBuildRetireZSKPush.../
// TestBuildKSKRolloverPush... below all check.
func dnskeysAndSigFromOps(t *testing.T, ops []dns.RR) (adds, deletes []*dns.DNSKEY, sig *dns.RRSIG) {
	t.Helper()
	for _, rr := range ops {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered != dns.TypeDNSKEY {
				continue
			}
			if sig != nil {
				t.Fatalf("expected exactly one RRSIG(DNSKEY), found a second: %s", v.String())
			}
			sig = v
		case *dns.DNSKEY:
			if rr.Header().Class == dns.ClassNONE {
				deletes = append(deletes, v)
			} else {
				adds = append(adds, v)
			}
		}
	}
	return adds, deletes, sig
}

func toRRSlice(keys []*dns.DNSKEY) []dns.RR {
	out := make([]dns.RR, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

// TestBuildAddZSKPushSignsCompleteResultingRRset is the regression test
// for the bug this whole family of functions exists to fix: an earlier
// version of this package (in cmd/sazuctl, before BuildAddZSKPush
// existed) signed only the newly added ZSK record in isolation, leaving
// the DNSKEY RRset with no RRSIG that actually covered what was served
// once a zone had more than the original KSK+ZSK pair. Verified here
// directly against a real RRSIG.Verify call, the same check a validating
// resolver performs.
func TestBuildAddZSKPushSignsCompleteResultingRRset(t *testing.T) {
	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zskA, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK A: %v", err)
	}
	zskB, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK B: %v", err)
	}

	m, err := BuildAddZSKPush("example.org.", []*dns.DNSKEY{ksk, zskA}, zskB, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildAddZSKPush: %v", err)
	}

	adds, deletes, sig := dnskeysAndSigFromOps(t, m.Ns)
	if len(deletes) != 0 {
		t.Fatalf("expected no deletes when only adding a key, got %+v", deletes)
	}
	if len(adds) != 3 {
		t.Fatalf("expected all 3 resulting keys re-asserted as adds, got %d: %+v", len(adds), adds)
	}
	if sig == nil {
		t.Fatalf("expected a covering RRSIG(DNSKEY) among the ops")
	}
	if err := sig.Verify(ksk, toRRSlice(adds)); err != nil {
		t.Fatalf("expected the RRSIG to validate against the complete resulting 3-key RRset, got %v", err)
	}
}

// TestBuildRetireZSKPushSignsCompleteRemainingRRsetAndDeletesRetired
// proves both halves of the fix: the retired key is explicitly deleted
// (never just implied by its absence from a fresh signature), and the
// fresh RRSIG covers exactly the remaining set -- provably not the
// stale, pre-retirement one, which is the failure this was found from.
func TestBuildRetireZSKPushSignsCompleteRemainingRRsetAndDeletesRetired(t *testing.T) {
	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	zskA, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK A: %v", err)
	}
	zskB, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK B: %v", err)
	}
	current := []*dns.DNSKEY{ksk, zskA, zskB}

	m, err := BuildRetireZSKPush("example.org.", current, zskB, ksk, kskPriv)
	if err != nil {
		t.Fatalf("BuildRetireZSKPush: %v", err)
	}

	adds, deletes, sig := dnskeysAndSigFromOps(t, m.Ns)
	if len(deletes) != 1 || deletes[0].PublicKey != zskB.PublicKey {
		t.Fatalf("expected exactly one delete, for the retired ZSK, got %+v", deletes)
	}
	if len(adds) != 2 {
		t.Fatalf("expected the 2 remaining keys re-asserted as adds, got %d: %+v", len(adds), adds)
	}
	if err := sig.Verify(ksk, toRRSlice(adds)); err != nil {
		t.Fatalf("expected the RRSIG to validate against the complete remaining 2-key RRset, got %v", err)
	}
	if err := sig.Verify(ksk, toRRSlice(current)); err == nil {
		t.Fatalf("expected the fresh RRSIG NOT to validate against the stale, pre-retirement 3-key set")
	}
}

// TestBuildKSKRolloverPushSignsCompleteResultingRRsetAndDeletesOldKSK
// proves a rollover explicitly removes the old KSK's own served record
// (never just left to linger once it's out of the key registry) and
// re-signs the complete resulting set (the new KSK plus every unchanged
// ZSK) with the new, self-signing KSK.
func TestBuildKSKRolloverPushSignsCompleteResultingRRsetAndDeletesOldKSK(t *testing.T) {
	oldKSK, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating old KSK: %v", err)
	}
	zskA, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK A: %v", err)
	}
	newKSK, newKSKPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating new KSK: %v", err)
	}

	m, err := BuildKSKRolloverPush("example.org.", []*dns.DNSKEY{oldKSK, zskA}, oldKSK, newKSK, newKSKPriv)
	if err != nil {
		t.Fatalf("BuildKSKRolloverPush: %v", err)
	}

	adds, deletes, sig := dnskeysAndSigFromOps(t, m.Ns)
	if len(deletes) != 1 || deletes[0].PublicKey != oldKSK.PublicKey {
		t.Fatalf("expected exactly one delete, for the old KSK, got %+v", deletes)
	}
	if len(adds) != 2 {
		t.Fatalf("expected the new KSK plus the unchanged ZSK re-asserted as adds, got %d: %+v", len(adds), adds)
	}
	if err := sig.Verify(newKSK, toRRSlice(adds)); err != nil {
		t.Fatalf("expected the RRSIG (self-signed by the new KSK) to validate against the complete resulting 2-key RRset, got %v", err)
	}
}
