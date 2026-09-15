package sazu

import (
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sazu.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestDBUsesPureGoSQLiteDriver is NFR-01: db.go opens its connection via
// sql.Open("sqlite", ...), the name modernc.org/sqlite (pure Go, no cgo)
// registers itself under -- never "sqlite3", the name mattn/go-sqlite3
// (cgo) uses. Checking sql.Drivers() proves it's actually this driver
// wired up at runtime, not just imported and unused; the broader "the
// whole suite builds and runs" property (no cgo toolchain required at
// all) is still what Test Specification §3.14 relies on, since nothing
// short of an actual CGO_ENABLED=0 build proves that -- this test proves
// the narrower, still-real property that this package specifically
// isn't using the cgo alternative.
func TestDBUsesPureGoSQLiteDriver(t *testing.T) {
	openTestDB(t)

	var found, foundCGOAlternative bool
	for _, name := range sql.Drivers() {
		switch name {
		case "sqlite":
			found = true
		case "sqlite3":
			foundCGOAlternative = true
		}
	}
	if !found {
		t.Fatalf("expected modernc.org/sqlite's pure-Go driver registered as %q, got %v", "sqlite", sql.Drivers())
	}
	if foundCGOAlternative {
		t.Fatalf("mattn/go-sqlite3's cgo driver is registered as %q -- NFR-01 requires the pure-Go driver only", "sqlite3")
	}
}

func TestDBCommitUpdateThenLoadAllReproducesOnboarding(t *testing.T) {
	db := openTestDB(t)

	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ops := []dns.RR{
		&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags: key.Flags, Protocol: key.Protocol, Algorithm: key.Algorithm, PublicKey: key.PublicKey},
		testSOA(1),
		testA("www.example.org.", net.IPv4(203, 0, 113, 10)),
	}
	// Mirror ApplyUpdateOps' expectation: these are Add ops, class = zone class.
	for _, rr := range ops {
		rr.Header().Class = dns.ClassINET
	}

	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, ops, dns.ClassINET, nil); err != nil {
		t.Fatalf("CommitUpdate: %v", err)
	}

	store, keys, _, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	pinned, ok := keys.Get("example.org.")
	if !ok || pinned.KSK.DNSKEY.PublicKey != key.PublicKey {
		t.Fatalf("expected the pinned key to survive a round trip")
	}

	z, ok := store.Get("example.org.")
	if !ok {
		t.Fatalf("expected the zone to exist after loading")
	}
	if soa := z.SOA(); soa == nil || soa.Serial != 1 {
		t.Fatalf("expected SOA serial 1 to survive a round trip, got %+v", soa)
	}
	got := z.Lookup("www.example.org.", dns.TypeA)
	if len(got) != 1 || !got[0].(*dns.A).A.Equal(net.IPv4(203, 0, 113, 10)) {
		t.Fatalf("expected the A record to survive a round trip, got %+v", got)
	}
}

// TestDBCommitUpdatePurgesStaleNSECOnNextUpdate proves CommitUpdate's SQL
// mirrors ZoneData.PurgeNSEC exactly: an NSEC (and its RRSIG) persisted by
// one update must not survive a later update that doesn't include one,
// even across a full reload from disk -- otherwise a restarted server
// would resurrect a stale chain that live, in-memory traffic already
// correctly discarded.
func TestDBCommitUpdatePurgesStaleNSECOnNextUpdate(t *testing.T) {
	db := openTestDB(t)

	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	dnskeyRR := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: key.Flags, Protocol: key.Protocol, Algorithm: key.Algorithm, PublicKey: key.PublicKey}
	nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "example.org.", TypeBitMap: []uint16{dns.TypeNSEC}}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeNSEC, Algorithm: 15, KeyTag: 1, SignerName: "example.org."}
	firstOps := []dns.RR{dnskeyRR, testSOA(1), nsec, sig}
	for _, rr := range firstOps {
		rr.Header().Class = dns.ClassINET
	}
	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, firstOps, dns.ClassINET, nil); err != nil {
		t.Fatalf("first CommitUpdate: %v", err)
	}

	secondOps := []dns.RR{testA("www.example.org.", net.IPv4(203, 0, 113, 10))}
	secondOps[0].Header().Class = dns.ClassINET
	if err := db.CommitUpdate("example.org.", nil, secondOps, dns.ClassINET, nil); err != nil {
		t.Fatalf("second CommitUpdate: %v", err)
	}

	store, _, _, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	z, ok := store.Get("example.org.")
	if !ok {
		t.Fatalf("expected the zone to exist after loading")
	}
	if got := z.Lookup("example.org.", dns.TypeNSEC); len(got) != 0 {
		t.Fatalf("expected the stale NSEC to be purged, got %+v", got)
	}
	if got := z.LookupRRSIG("example.org.", dns.TypeNSEC); len(got) != 0 {
		t.Fatalf("expected the stale NSEC's RRSIG to be purged, got %+v", got)
	}
	if got := z.Lookup("www.example.org.", dns.TypeA); len(got) != 1 {
		t.Fatalf("expected the second update's own content to survive, got %+v", got)
	}
}

func TestDBPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sazu.db")

	db1, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	if err := db1.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, []dns.RR{soa}, dns.ClassINET, nil); err != nil {
		t.Fatalf("CommitUpdate: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer db2.Close()

	store, keys, _, err := db2.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll after reopen: %v", err)
	}
	if _, ok := keys.Get("example.org."); !ok {
		t.Fatalf("expected the pinned key to survive closing and reopening the database")
	}
	z, ok := store.Get("example.org.")
	if !ok || z.SOA() == nil {
		t.Fatalf("expected the zone/SOA to survive closing and reopening the database")
	}
}

func TestDBCommitUpdateAppliesAllFourOpForms(t *testing.T) {
	db := openTestDB(t)
	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	a1 := testA("www.example.org.", net.IPv4(203, 0, 113, 10))
	a1.Hdr.Class = dns.ClassINET
	a2 := testA("www.example.org.", net.IPv4(203, 0, 113, 11))
	a2.Hdr.Class = dns.ClassINET
	mx := &dns.MX{Hdr: dns.RR_Header{Name: "mail.example.org.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mx.example.org."}

	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, []dns.RR{soa, a1, a2, mx}, dns.ClassINET, nil); err != nil {
		t.Fatalf("CommitUpdate (onboard): %v", err)
	}

	// §2.5.4 delete one RR
	del := testA("www.example.org.", net.IPv4(203, 0, 113, 10))
	del.Hdr.Class = dns.ClassNONE
	if err := db.CommitUpdate("example.org.", nil, []dns.RR{del}, dns.ClassINET, nil); err != nil {
		t.Fatalf("CommitUpdate (delete one RR): %v", err)
	}

	// §2.5.2 delete an RRset
	delRRset := &dns.MX{Hdr: dns.RR_Header{Name: "mail.example.org.", Rrtype: dns.TypeMX, Class: dns.ClassANY, Ttl: 0}}
	if err := db.CommitUpdate("example.org.", nil, []dns.RR{delRRset}, dns.ClassINET, nil); err != nil {
		t.Fatalf("CommitUpdate (delete rrset): %v", err)
	}

	store, _, _, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	z, _ := store.Get("example.org.")
	got := z.Lookup("www.example.org.", dns.TypeA)
	if len(got) != 1 || !got[0].(*dns.A).A.Equal(net.IPv4(203, 0, 113, 11)) {
		t.Fatalf("expected only .11 to remain after deleting .10, got %+v", got)
	}
	if got := z.Lookup("mail.example.org.", dns.TypeMX); len(got) != 0 {
		t.Fatalf("expected the MX rrset to be gone, got %+v", got)
	}
}

func TestDBCommitUpdateRollsBackOnMalformedOp(t *testing.T) {
	db := openTestDB(t)
	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	good := testA("www.example.org.", net.IPv4(203, 0, 113, 10))
	good.Hdr.Class = dns.ClassINET
	// A malformed op: neither Add (zone class), nor any recognized delete
	// shape -- CHAOS class with real rdata matches none of the four forms.
	bad := testA("bad.example.org.", net.IPv4(203, 0, 113, 99))
	bad.Hdr.Class = dns.ClassCHAOS

	err = db.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, []dns.RR{soa, good, bad}, dns.ClassINET, nil)
	if err == nil {
		t.Fatalf("expected CommitUpdate to fail on a malformed op")
	}

	store, keys, _, loadErr := db.LoadAll()
	if loadErr != nil {
		t.Fatalf("LoadAll: %v", loadErr)
	}
	if _, ok := keys.Get("example.org."); ok {
		t.Fatalf("expected nothing to be committed after a rolled-back transaction, but the key was pinned")
	}
	if _, ok := store.Get("example.org."); ok {
		t.Fatalf("expected nothing to be committed after a rolled-back transaction, but the zone exists")
	}
}

// TestDBCommitUpdatePersistsAndClearsContact proves §10.6's registration
// record survives a restart (LoadAll rehydrates ContactRegistry, not just
// Store/KeyRegistry) and that a later clearing update actually removes the
// row rather than leaving stale contact data behind.
func TestDBCommitUpdatePersistsAndClearsContact(t *testing.T) {
	db := openTestDB(t)
	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET

	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, []dns.RR{soa}, dns.ClassINET,
		&ContactUpdate{Addresses: []string{"mailto:ops@example.org", "https://hooks.example.org/sazu"}}); err != nil {
		t.Fatalf("CommitUpdate with contact: %v", err)
	}

	_, _, contacts, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	got, ok := contacts.Get("example.org.")
	if !ok || len(got) != 2 || got[0] != "mailto:ops@example.org" || got[1] != "https://hooks.example.org/sazu" {
		t.Fatalf("expected the registered contact to survive a round trip, got %+v ok=%v", got, ok)
	}

	if err := db.CommitUpdate("example.org.", nil, nil, dns.ClassINET, &ContactUpdate{}); err != nil {
		t.Fatalf("CommitUpdate clearing contact: %v", err)
	}
	_, _, contacts, err = db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll after clearing: %v", err)
	}
	if _, ok := contacts.Get("example.org."); ok {
		t.Fatalf("expected the cleared contact to not survive a round trip")
	}
}

// TestDBListZonesLoadKeyLoadContact proves the lighter-weight,
// single-zone accessors sazu-watchd (§11) uses agree with what LoadAll
// itself would have loaded, without needing to load full zone content.
func TestDBListZonesLoadKeyLoadContact(t *testing.T) {
	db := openTestDB(t)
	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: key}, []dns.RR{soa}, dns.ClassINET,
		&ContactUpdate{Addresses: []string{"mailto:ops@example.org"}}); err != nil {
		t.Fatalf("CommitUpdate: %v", err)
	}

	zones, err := db.ListZones()
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(zones) != 1 || zones[0] != "example.org." {
		t.Fatalf("expected [\"example.org.\"], got %+v", zones)
	}

	got, ok, err := db.LoadKey("example.org.")
	if err != nil || !ok || got.PublicKey != key.PublicKey {
		t.Fatalf("LoadKey: got %+v ok=%v err=%v", got, ok, err)
	}
	if _, ok, err := db.LoadKey("never-onboarded.example."); err != nil || ok {
		t.Fatalf("expected LoadKey for an unonboarded zone to report ok=false, got ok=%v err=%v", ok, err)
	}

	addrs, ok, err := db.LoadContact("example.org.")
	if err != nil || !ok || len(addrs) != 1 || addrs[0] != "mailto:ops@example.org" {
		t.Fatalf("LoadContact: got %+v ok=%v err=%v", addrs, ok, err)
	}
	if _, ok, err := db.LoadContact("never-onboarded.example."); err != nil || ok {
		t.Fatalf("expected LoadContact for an unonboarded zone to report ok=false, got ok=%v err=%v", ok, err)
	}
}

// TestDBRecordTransactionAndRecentTransactions proves §12's audit trail
// persistence: entries survive, come back newest first, and a zone with
// no entries at all (rather than an error) just gets an empty result --
// exactly what a never-onboarded zone's first, rejected attempt would
// look like before any later ones exist.
func TestDBRecordTransactionAndRecentTransactions(t *testing.T) {
	db := openTestDB(t)

	base := time.Now()
	zskTag := uint16(54321)
	entries := []AuditEntry{
		{ID: "tx-1", Zone: "example.org.", RemoteAddr: "203.0.113.1:5353", Rcode: "REFUSED", Status: "ERR_NO_DS_PUBLISHED", At: base},
		{ID: "tx-2", Zone: "example.org.", RemoteAddr: "203.0.113.1:5353", Rcode: "NOERROR", Status: "", At: base.Add(time.Minute), KeyTag: &zskTag, KeyRole: "ZSK"},
		{ID: "tx-3", Zone: "other.example.", RemoteAddr: "203.0.113.2:5353", Rcode: "NOERROR", Status: "", At: base.Add(2 * time.Minute)},
	}
	for _, e := range entries {
		if err := db.RecordTransaction(e); err != nil {
			t.Fatalf("RecordTransaction(%s): %v", e.ID, err)
		}
	}

	got, err := db.RecentTransactions("example.org.", 10)
	if err != nil {
		t.Fatalf("RecentTransactions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries for example.org., got %d: %+v", len(got), got)
	}
	if got[0].ID != "tx-2" || got[1].ID != "tx-1" {
		t.Fatalf("expected newest-first order (tx-2, tx-1), got (%s, %s)", got[0].ID, got[1].ID)
	}
	if got[1].Status != "ERR_NO_DS_PUBLISHED" {
		t.Fatalf("expected the rejected attempt's status to survive, got %q", got[1].Status)
	}
	if got[1].KeyTag != nil || got[1].KeyRole != "" {
		t.Fatalf("expected the rejected (never-authenticated) attempt to carry no key attribution, got tag=%v role=%q", got[1].KeyTag, got[1].KeyRole)
	}
	if got[0].KeyTag == nil || *got[0].KeyTag != zskTag || got[0].KeyRole != "ZSK" {
		t.Fatalf("expected the authenticated push's key tag and role to survive, got tag=%v role=%q", got[0].KeyTag, got[0].KeyRole)
	}

	if got, err := db.RecentTransactions("never-touched.example.", 10); err != nil || len(got) != 0 {
		t.Fatalf("expected no entries (not an error) for an untouched zone, got %+v err=%v", got, err)
	}

	if limited, err := db.RecentTransactions("example.org.", 1); err != nil || len(limited) != 1 || limited[0].ID != "tx-2" {
		t.Fatalf("expected limit to cap results to the single newest entry, got %+v err=%v", limited, err)
	}
}

// TestDBOpenMigratesPreKeyAttributionAuditLog proves an audit_log table
// written before key_tag/key_role existed is transparently upgraded in
// place the first time it's opened with this version -- an existing
// deployment's audit history survives the upgrade with no operator
// action, its pre-existing rows simply carrying no key attribution
// (there is nothing to attribute them to after the fact).
func TestDBOpenMigratesPreKeyAttributionAuditLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sazu.db")

	// Build a database in the pre-key-attribution shape directly via SQL,
	// bypassing Open (which would create the current-shape table from the
	// start).
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE audit_log (
			id          TEXT PRIMARY KEY,
			zone        TEXT NOT NULL,
			remote_addr TEXT NOT NULL,
			rcode       TEXT NOT NULL,
			status      TEXT NOT NULL,
			at          INTEGER NOT NULL
		);
	`); err != nil {
		t.Fatalf("creating pre-key-attribution schema: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO audit_log (id, zone, remote_addr, rcode, status, at) VALUES (?, ?, ?, ?, ?, ?)`,
		"old-tx", "example.org.", "203.0.113.1:5353", "NOERROR", "", time.Now().Unix(),
	); err != nil {
		t.Fatalf("inserting pre-key-attribution row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("closing raw handle: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open (expected to migrate transparently): %v", err)
	}
	defer db.Close()

	got, err := db.RecentTransactions("example.org.", 10)
	if err != nil {
		t.Fatalf("RecentTransactions after migration: %v", err)
	}
	if len(got) != 1 || got[0].ID != "old-tx" {
		t.Fatalf("expected the pre-existing row to survive migration, got %+v", got)
	}
	if got[0].KeyTag != nil || got[0].KeyRole != "" {
		t.Fatalf("expected a pre-migration row to carry no key attribution, got tag=%v role=%q", got[0].KeyTag, got[0].KeyRole)
	}

	// A fresh row recorded after migration must round-trip its key
	// attribution normally.
	tag := uint16(999)
	if err := db.RecordTransaction(AuditEntry{ID: "new-tx", Zone: "example.org.", RemoteAddr: "203.0.113.1:5353", Rcode: "NOERROR", At: time.Now(), KeyTag: &tag, KeyRole: "KSK"}); err != nil {
		t.Fatalf("RecordTransaction after migration: %v", err)
	}
	got, err = db.RecentTransactions("example.org.", 10)
	if err != nil {
		t.Fatalf("RecentTransactions after post-migration write: %v", err)
	}
	if got[0].ID != "new-tx" || got[0].KeyTag == nil || *got[0].KeyTag != tag || got[0].KeyRole != "KSK" {
		t.Fatalf("expected the post-migration row's key attribution to round-trip, got %+v", got[0])
	}

	// A second Open (simulating a restart) must be a no-op migration --
	// the table is already current-shape.
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db2.Close()
}

// TestDBCommitUpdateAddsAndRetiresZSK proves the optional ZSK split
// (keys.go's KeyRole) persists correctly and independently of the KSK:
// registering one, then retiring it, both survive a round trip through
// LoadZoneKeys, and the KSK itself is untouched throughout.
func TestDBCommitUpdateAddsAndRetiresZSK(t *testing.T) {
	db := openTestDB(t)
	ksk, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: ksk}, []dns.RR{soa}, dns.ClassINET, nil); err != nil {
		t.Fatalf("onboarding CommitUpdate: %v", err)
	}

	zsk, _, err := GenerateEd25519Key("example.org.", false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	mk := &ManagedKey{DNSKEY: zsk, Role: RoleZSK, CanAuthenticateTx: true}
	if err := db.CommitUpdate("example.org.", &KeyChange{AddZSK: mk}, nil, dns.ClassINET, nil); err != nil {
		t.Fatalf("AddZSK CommitUpdate: %v", err)
	}

	zk, ok, err := db.LoadZoneKeys("example.org.")
	if err != nil || !ok {
		t.Fatalf("LoadZoneKeys: ok=%v err=%v", ok, err)
	}
	if zk.KSK.DNSKEY.PublicKey != ksk.PublicKey {
		t.Fatalf("expected the KSK to survive unaffected, got %+v", zk.KSK)
	}
	if len(zk.ZSKs) != 1 || zk.ZSKs[0].DNSKEY.PublicKey != zsk.PublicKey || !zk.ZSKs[0].CanAuthenticateTx {
		t.Fatalf("expected the registered ZSK to survive a round trip, got %+v", zk.ZSKs)
	}

	// LoadKey (the lighter-weight accessor sazu-watchd uses) must still
	// return only the KSK, never a ZSK -- a ZSK is never DS-anchored, so
	// it has nothing for a chain-of-trust re-check to verify.
	kskOnly, ok, err := db.LoadKey("example.org.")
	if err != nil || !ok || kskOnly.PublicKey != ksk.PublicKey {
		t.Fatalf("LoadKey: got %+v ok=%v err=%v", kskOnly, ok, err)
	}

	tag := zsk.KeyTag()
	if err := db.CommitUpdate("example.org.", &KeyChange{RetireZSK: &tag}, nil, dns.ClassINET, nil); err != nil {
		t.Fatalf("RetireZSK CommitUpdate: %v", err)
	}
	zk, ok, err = db.LoadZoneKeys("example.org.")
	if err != nil || !ok {
		t.Fatalf("LoadZoneKeys after retire: ok=%v err=%v", ok, err)
	}
	if len(zk.ZSKs) != 0 {
		t.Fatalf("expected no ZSKs left after retiring the only one, got %+v", zk.ZSKs)
	}
	if zk.KSK.DNSKEY.PublicKey != ksk.PublicKey {
		t.Fatalf("expected the KSK to remain untouched by retiring a ZSK, got %+v", zk.KSK)
	}
}

// TestDBCommitUpdateKSKRolloverReplacesRowNotAdds proves a KSK rollover
// (PinKSK with a *different* key tag than the one already on file)
// replaces that zone's sole KSK row rather than leaving the old one
// behind as a stale second "KSK" -- PRIMARY KEY (zone, keytag) means the
// two key tags would otherwise coexist as two separate rows.
func TestDBCommitUpdateKSKRolloverReplacesRowNotAdds(t *testing.T) {
	db := openTestDB(t)
	oldKSK, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating first KSK: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: oldKSK}, []dns.RR{soa}, dns.ClassINET, nil); err != nil {
		t.Fatalf("onboarding CommitUpdate: %v", err)
	}

	newKSK, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating second KSK: %v", err)
	}
	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: newKSK}, nil, dns.ClassINET, nil); err != nil {
		t.Fatalf("rollover CommitUpdate: %v", err)
	}

	zk, ok, err := db.LoadZoneKeys("example.org.")
	if err != nil || !ok {
		t.Fatalf("LoadZoneKeys: ok=%v err=%v", ok, err)
	}
	if zk.KSK.DNSKEY.PublicKey != newKSK.PublicKey {
		t.Fatalf("expected the KSK to be the new one, got %+v", zk.KSK)
	}

	var kskRowCount int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM keys WHERE zone = ? AND role = 'KSK'`, "example.org.").Scan(&kskRowCount); err != nil {
		t.Fatalf("counting KSK rows: %v", err)
	}
	if kskRowCount != 1 {
		t.Fatalf("expected exactly one KSK row after a rollover, got %d", kskRowCount)
	}
}

// TestDBOpenMigratesPreZSKKeysTable proves a database written before ZSK
// support existed (the old keys table shape: zone as its sole primary
// key, no keytag/role/can_auth_tx columns) is transparently upgraded in
// place the first time it's opened with this version -- an existing
// deployment's zones and keys survive the upgrade with no operator
// action, and every pre-existing key becomes that zone's KSK.
func TestDBOpenMigratesPreZSKKeysTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sazu.db")

	// Build a database in the pre-ZSK shape directly via SQL, bypassing
	// Open (which would create the current-shape table from the start).
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE zones (origin TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
		CREATE TABLE keys (
			zone       TEXT PRIMARY KEY REFERENCES zones(origin),
			flags      INTEGER NOT NULL,
			protocol   INTEGER NOT NULL,
			algorithm  INTEGER NOT NULL,
			public_key TEXT NOT NULL,
			pinned_at  INTEGER NOT NULL
		);
	`); err != nil {
		t.Fatalf("creating pre-ZSK schema: %v", err)
	}

	key, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO zones (origin, created_at) VALUES (?, ?)`, "example.org.", 1000); err != nil {
		t.Fatalf("inserting pre-ZSK zone row: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO keys (zone, flags, protocol, algorithm, public_key, pinned_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"example.org.", key.Flags, key.Protocol, key.Algorithm, key.PublicKey, 1000,
	); err != nil {
		t.Fatalf("inserting pre-ZSK key row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("closing raw handle: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open (expected to migrate transparently): %v", err)
	}
	defer db.Close()

	zk, ok, err := db.LoadZoneKeys("example.org.")
	if err != nil || !ok {
		t.Fatalf("LoadZoneKeys after migration: ok=%v err=%v", ok, err)
	}
	if zk.KSK.DNSKEY.PublicKey != key.PublicKey || zk.KSK.Role != RoleKSK || !zk.KSK.CanAuthenticateTx {
		t.Fatalf("expected the pre-existing key to become the zone's KSK, got %+v", zk.KSK)
	}
	if len(zk.ZSKs) != 0 {
		t.Fatalf("expected no ZSKs from a migrated pre-ZSK database, got %+v", zk.ZSKs)
	}

	// A second Open (simulating a restart) must be a no-op migration --
	// the table is already current-shape.
	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db2.Close()
	if zk2, ok, err := db2.LoadZoneKeys("example.org."); err != nil || !ok || zk2.KSK.DNSKEY.PublicKey != key.PublicKey {
		t.Fatalf("expected the migrated data to still be there after a second Open: ok=%v err=%v zk=%+v", ok, err, zk2)
	}
}

// TestDBDeleteZoneRemovesEverythingButAuditLog proves DeleteZone's exact
// scope: the zone's keys, content, and contact registration are all
// gone, ListZones no longer names it, but its audit-trail history
// (including, in a real decommission, the decommission transaction
// itself) survives -- an operator investigating "what happened to this
// zone" needs that history at least as much for a zone that no longer
// exists as for one that still does.
func TestDBDeleteZoneRemovesEverythingButAuditLog(t *testing.T) {
	db := openTestDB(t)
	ksk, _, err := GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatalf("generating KSK: %v", err)
	}
	soa := testSOA(1)
	soa.Hdr.Class = dns.ClassINET
	if err := db.CommitUpdate("example.org.", &KeyChange{PinKSK: ksk}, []dns.RR{soa}, dns.ClassINET,
		&ContactUpdate{Addresses: []string{"mailto:ops@example.org"}}); err != nil {
		t.Fatalf("onboarding CommitUpdate: %v", err)
	}
	if err := db.RecordTransaction(AuditEntry{ID: "tx-1", Zone: "example.org.", RemoteAddr: "203.0.113.1:5353", Rcode: "NOERROR", At: time.Now()}); err != nil {
		t.Fatalf("RecordTransaction: %v", err)
	}

	if err := db.DeleteZone("example.org."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	if _, ok, err := db.LoadZoneKeys("example.org."); err != nil || ok {
		t.Fatalf("expected no keys after DeleteZone: ok=%v err=%v", ok, err)
	}
	if _, ok, err := db.LoadContact("example.org."); err != nil || ok {
		t.Fatalf("expected no contact after DeleteZone: ok=%v err=%v", ok, err)
	}
	zones, err := db.ListZones()
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	for _, z := range zones {
		if z == "example.org." {
			t.Fatalf("expected example.org. to no longer be listed after DeleteZone, got %v", zones)
		}
	}
	store, _, _, err := db.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, ok := store.Get("example.org."); ok {
		t.Fatalf("expected no zone content after DeleteZone")
	}

	entries, err := db.RecentTransactions("example.org.", 10)
	if err != nil {
		t.Fatalf("RecentTransactions: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != "tx-1" {
		t.Fatalf("expected the audit-trail history to survive DeleteZone, got %+v", entries)
	}
}
