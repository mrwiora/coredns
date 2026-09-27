package sazu

import (
	"crypto/ed25519"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newVersionedTestSazu is newTestSazu with the version check enforced,
// as setup.go always does.
func newVersionedTestSazu(zone string) *Sazu {
	s := newTestSazu(zone)
	s.SkipVersionCheck = false
	return s
}

// withVersion adds zone's version prerequisite to m.
func withVersion(m *dns.Msg, zone string, v uint64) *dns.Msg {
	m.Answer = append(m.Answer, BuildVersionPrereq(zone, v))
	return m
}

func signNow(t *testing.T, m *dns.Msg, key *dns.DNSKEY, priv ed25519.PrivateKey) []byte {
	t.Helper()
	now := time.Now()
	wire, err := SignUpdate(m, key, priv, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	return wire
}

// queryVersion reads zone's published version from addr.
func queryVersion(t *testing.T, addr, zone string) uint64 {
	t.Helper()
	resp := query(t, addr, VersionOwnerName(zone), dns.TypeTXT)
	if len(resp.Answer) != 1 {
		t.Fatalf("expected one version TXT for %s, got %+v", zone, resp.Answer)
	}
	v, err := strconv.ParseUint(resp.Answer[0].(*dns.TXT).Txt[0], 10, 64)
	if err != nil {
		t.Fatalf("parsing version: %v", err)
	}
	return v
}

// onboardVersioned onboards example.org. (KSK + ZSK, no content) with
// the version prerequisite, and returns the keys.
func onboardVersioned(t *testing.T, addr string) (ksk *dns.DNSKEY, kskPriv ed25519.PrivateKey, zsk *dns.DNSKEY, zskPriv ed25519.PrivateKey) {
	t.Helper()
	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	zsk, zskPriv, err = GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatal(err)
	}
	withVersion(trust, "example.org.", queryVersion(t, addr, "example.org."))
	if resp := sendRaw(t, addr, signNow(t, trust, ksk, kskPriv)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	return ksk, kskPriv, zsk, zskPriv
}

// TestVersionIsPublishedAndStartsAtZero: an in-scope zone never seen
// before is at version 0; each accepted control change increments it.
func TestVersionIsPublishedAndStartsAtZero(t *testing.T) {
	s := newVersionedTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	if v := queryVersion(t, addr, "example.org."); v != 0 {
		t.Fatalf("expected version 0 before onboarding, got %d", v)
	}
	onboardVersioned(t, addr)
	if v := queryVersion(t, addr, "example.org."); v != 1 {
		t.Fatalf("expected version 1 after onboarding, got %d", v)
	}
}

// TestControlChangeWithoutVersionIsRefused: onboarding, key and contact
// changes must name the version.
func TestControlChangeWithoutVersionIsRefused(t *testing.T) {
	s := newVersionedTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	zsk, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatal(err)
	}
	expectRefusedWith(t, "unversioned onboarding", sendRaw(t, addr, signNow(t, trust, ksk, kskPriv)), dns.RcodeRefused, statusErrVersionRequired)
	if _, ok := s.Keys.Get("example.org."); ok {
		t.Fatalf("expected nothing pinned")
	}

	ksk, kskPriv, _, _ = onboardVersioned(t, addr)
	op, err := BuildContactOp("example.org.", []string{"mailto:ops@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	contact := new(dns.Msg)
	contact.SetUpdate("example.org.")
	contact.Insert([]dns.RR{op})
	expectRefusedWith(t, "unversioned contact change", sendRaw(t, addr, signNow(t, contact, ksk, kskPriv)), dns.RcodeRefused, statusErrVersionRequired)
}

// TestReplayedAddZSKCannotUnretireAKey is the motivating attack: capture
// a KSK-signed add-zsk, wait for that ZSK to be retired, replay the
// capture. The version it names has long moved on.
func TestReplayedAddZSKCannotUnretireAKey(t *testing.T) {
	s := newVersionedTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardVersioned(t, addr)

	extra, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatal(err)
	}
	add, err := BuildAddZSKPush("example.org.", currentDNSKEYs(t, addr), extra, ksk, kskPriv)
	if err != nil {
		t.Fatal(err)
	}
	captured := signNow(t, withVersion(add, "example.org.", queryVersion(t, addr, "example.org.")), ksk, kskPriv)
	if resp := sendRaw(t, addr, captured); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("add-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	// An exact replay right away is already stale.
	expectRefusedWith(t, "immediate replay", sendRaw(t, addr, captured), dns.RcodeNXRrset, statusErrStaleVersion)

	retire, err := BuildRetireZSKPush("example.org.", currentDNSKEYs(t, addr), extra, ksk, kskPriv)
	if err != nil {
		t.Fatal(err)
	}
	withVersion(retire, "example.org.", queryVersion(t, addr, "example.org."))
	if resp := sendRaw(t, addr, signNow(t, retire, ksk, kskPriv)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("retire-zsk rcode = %s", dns.RcodeToString[resp.Rcode])
	}

	expectRefusedWith(t, "replayed add-zsk", sendRaw(t, addr, captured), dns.RcodeNXRrset, statusErrStaleVersion)
	zk, _ := s.Keys.Get("example.org.")
	if _, ok := zk.FindZSK(extra.KeyTag()); ok {
		t.Fatalf("expected the retired ZSK to stay retired")
	}
}

// TestTwoControlChangesSignedForTheSameVersion: only one of them can
// apply; the other must be re-read and re-signed. This is what orders
// control changes without any clock.
func TestTwoControlChangesSignedForTheSameVersion(t *testing.T) {
	s := newVersionedTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardVersioned(t, addr)
	v := queryVersion(t, addr, "example.org.")

	contact := func(address string) []byte {
		op, err := BuildContactOp("example.org.", []string{address})
		if err != nil {
			t.Fatal(err)
		}
		m := new(dns.Msg)
		m.SetUpdate("example.org.")
		m.Insert([]dns.RR{op})
		return signNow(t, withVersion(m, "example.org.", v), ksk, kskPriv)
	}
	first, second := contact("mailto:first@example.org"), contact("mailto:second@example.org")
	if resp := sendRaw(t, addr, first); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	expectRefusedWith(t, "second change for the same version", sendRaw(t, addr, second), dns.RcodeNXRrset, statusErrStaleVersion)
	if addrs, _ := s.Contacts.Get("example.org."); len(addrs) != 1 || addrs[0] != "mailto:first@example.org" {
		t.Fatalf("contact = %v", addrs)
	}
}

// TestContentPushesUseTheSerialNotTheVersion: the first content push
// needs the version (no serial yet); later ones don't, and don't change
// it -- so a KSK operation prepared offline stays valid across routine
// content pushes.
func TestContentPushesUseTheSerialNotTheVersion(t *testing.T) {
	s := newVersionedTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, zsk, zskPriv := onboardVersioned(t, addr)
	v := queryVersion(t, addr, "example.org.")

	// Prepared "offline" now, sent after the content pushes below.
	op, err := BuildContactOp("example.org.", []string{"mailto:ops@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	prepared := new(dns.Msg)
	prepared.SetUpdate("example.org.")
	prepared.Insert([]dns.RR{op})
	preparedWire := signNow(t, withVersion(prepared, "example.org.", v), ksk, kskPriv)

	push := func(serial uint32, version *uint64) *dns.Msg {
		m, err := BuildContentPush("example.org.", testSOA(serial), []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, byte(serial)))}, zsk, zskPriv, nil)
		if err != nil {
			t.Fatal(err)
		}
		if version != nil {
			withVersion(m, "example.org.", *version)
		}
		return sendRaw(t, addr, signNow(t, m, zsk, zskPriv))
	}

	expectRefusedWith(t, "first content push without version", push(1, nil), dns.RcodeRefused, statusErrVersionRequired)
	if resp := push(1, &v); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first content push rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if resp := push(2, nil); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("second content push rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if got := queryVersion(t, addr, "example.org."); got != v {
		t.Fatalf("content pushes changed the version: %d -> %d", v, got)
	}
	if resp := sendRaw(t, addr, preparedWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("offline-prepared contact change rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
}

// TestDecommissionedZoneCannotBeRecreatedByAReplay: the version survives
// decommission -- in memory and across a restart -- so the zone's old
// onboarding message can't bring it back.
func TestDecommissionedZoneCannotBeRecreatedByAReplay(t *testing.T) {
	db := openTestDB(t)
	s := newVersionedTestSazu("example.org.")
	s.DB = db
	addr := serveThroughRealServer(t, s)

	ksk, kskPriv, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	zsk, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := BuildTrustPush("example.org.", ksk, kskPriv, zsk)
	if err != nil {
		t.Fatal(err)
	}
	onboardWire := signNow(t, withVersion(trust, "example.org.", 0), ksk, kskPriv)
	if resp := sendRaw(t, addr, onboardWire); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("onboarding rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	decom := withVersion(BuildDecommissionPush("example.org."), "example.org.", 1)
	if resp := sendRaw(t, addr, signNow(t, decom, ksk, kskPriv)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("decommission rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if v := queryVersion(t, addr, "example.org."); v != 2 {
		t.Fatalf("expected decommission to leave version 2, got %d", v)
	}
	expectRefusedWith(t, "replayed onboarding after decommission", sendRaw(t, addr, onboardWire), dns.RcodeNXRrset, statusErrStaleVersion)

	// A fresh server over the same database, as after a restart.
	versions, err := db.LoadVersions()
	if err != nil {
		t.Fatalf("LoadVersions: %v", err)
	}
	store, keys, contacts, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	s2 := newVersionedTestSazu("example.org.")
	s2.Store, s2.Keys, s2.Contacts, s2.DB = store, keys, contacts, db
	for zone, v := range versions {
		s2.Versions.Set(zone, v)
	}
	addr2 := serveThroughRealServer(t, s2)
	expectRefusedWith(t, "replayed onboarding after restart", sendRaw(t, addr2, onboardWire), dns.RcodeNXRrset, statusErrStaleVersion)
	if _, ok := s2.Keys.Get("example.org."); ok {
		t.Fatalf("expected the replay to not re-onboard the zone")
	}
}

// TestVersionNameIsReserved: nobody can write to the version name.
func TestVersionNameIsReserved(t *testing.T) {
	s := newVersionedTestSazu("example.org.")
	addr := serveThroughRealServer(t, s)
	ksk, kskPriv, _, _ := onboardVersioned(t, addr)
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Insert([]dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: VersionOwnerName("example.org."), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"999"}}})
	withVersion(m, "example.org.", queryVersion(t, addr, "example.org."))
	if resp := sendRaw(t, addr, signNow(t, m, ksk, kskPriv)); resp.Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}
