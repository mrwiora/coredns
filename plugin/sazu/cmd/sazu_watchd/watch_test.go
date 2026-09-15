package main

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/coredns/coredns/plugin/sazu"

	"github.com/miekg/dns"
)

// fakeValidator lets tests control exactly what VerifyChainOfTrust
// returns per zone, without any real network query -- chain.go's own
// tests already cover the real DNS-querying logic; this covers what
// checkOnce does with its result.
type fakeValidator struct {
	err map[string]error // zone -> error to return; nil/absent means success
}

func (f fakeValidator) VerifyChainOfTrust(zone string, _ *dns.DNSKEY) error {
	return f.err[zone]
}

// fakeDNSKEYFetcher lets tests control exactly what a zone's live
// DNSKEY RRset "contains," without any real DNS query -- dnskey.go's
// own liveDNSKEYFetcher is the real implementation this stands in for.
type fakeDNSKEYFetcher struct {
	served map[string]map[uint16]bool // zone -> key tags currently "served"
	err    map[string]error           // zone -> error to return instead
}

func (f fakeDNSKEYFetcher) FetchServedDNSKEYTags(zone string) (map[uint16]bool, error) {
	if err, ok := f.err[zone]; ok {
		return nil, err
	}
	return f.served[zone], nil
}

func openTestDB(t *testing.T) *sazu.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sazu.db")
	db, err := sazu.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func onboardTestZone(t *testing.T, db *sazu.DB, zone string, contacts ...string) {
	t.Helper()
	key, _, err := sazu.GenerateEd25519Key(zone, true)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns: "ns1." + dns.Fqdn(zone), Mbox: "hostmaster." + dns.Fqdn(zone), Serial: 1, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 3600}
	var contactUpdate *sazu.ContactUpdate
	if len(contacts) > 0 {
		contactUpdate = &sazu.ContactUpdate{Addresses: contacts}
	}
	if err := db.CommitUpdate(zone, &sazu.KeyChange{PinKSK: key}, []dns.RR{soa}, dns.ClassINET, contactUpdate); err != nil {
		t.Fatalf("CommitUpdate: %v", err)
	}
}

func TestCheckOnceFirstObservationEstablishesBaselineWithoutAlerting(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.", "mailto:ops@example.org")

	// Already failing the very first time it's ever observed.
	v := fakeValidator{err: map[string]error{"example.org.": fmt.Errorf("no DS published")}}
	state := make(map[string]*zoneState)

	alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
	if err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alert on first observation, got %+v", alerts)
	}
	if state["example.org."] == nil || state["example.org."].lastOK {
		t.Fatalf("expected the baseline to record the failing state")
	}
}

func TestCheckOnceAlertsOnTransitionFromOKToFailing(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.", "mailto:ops@example.org")

	v := fakeValidator{}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}

	v.err = map[string]error{"example.org.": fmt.Errorf("no DS published")}
	alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one alert, got %+v", alerts)
	}
	a := alerts[0]
	if a.Zone != "example.org." || a.Recovered || a.Err == nil {
		t.Fatalf("unexpected alert shape: %+v", a)
	}
	if len(a.Addresses) != 1 || a.Addresses[0] != "mailto:ops@example.org" {
		t.Fatalf("expected the registered contact address, got %+v", a.Addresses)
	}
}

func TestCheckOnceAlertsOnRecovery(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")

	v := fakeValidator{err: map[string]error{"example.org.": fmt.Errorf("no DS published")}}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}

	v.err = nil
	alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 || !alerts[0].Recovered || alerts[0].Err != nil {
		t.Fatalf("expected exactly one recovery alert, got %+v", alerts)
	}
}

func TestCheckOnceStaysSilentAcrossRepeatedIdenticalOutcomes(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")

	v := fakeValidator{}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}
	for i := 0; i < 3; i++ {
		alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
		if err != nil {
			t.Fatalf("checkOnce %d: %v", i, err)
		}
		if len(alerts) != 0 {
			t.Fatalf("checkOnce %d: expected no alert while the outcome stays the same, got %+v", i, alerts)
		}
	}
}

func TestCheckOnceHandlesMultipleZonesIndependently(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "a.example.")
	onboardTestZone(t, db, "b.example.")

	v := fakeValidator{}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}

	v.err = map[string]error{"a.example.": fmt.Errorf("broken")}
	alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Zone != "a.example." {
		t.Fatalf("expected only a.example. to alert, got %+v", alerts)
	}
}

// registerTestZSK adds a ZSK to an already-onboarded zone, returning its
// key tag for the test to reference.
func registerTestZSK(t *testing.T, db *sazu.DB, zone string) uint16 {
	t.Helper()
	zsk, _, err := sazu.GenerateEd25519Key(zone, false)
	if err != nil {
		t.Fatalf("generating ZSK: %v", err)
	}
	change := &sazu.KeyChange{AddZSK: &sazu.ManagedKey{DNSKEY: zsk, Role: sazu.RoleZSK, CanAuthenticateTx: true}}
	if err := db.CommitUpdate(zone, change, nil, dns.ClassINET, nil); err != nil {
		t.Fatalf("registering ZSK: %v", err)
	}
	return zsk.KeyTag()
}

func TestCheckOnceZSKPresenceFirstObservationEstablishesBaselineWithoutAlerting(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.", "mailto:ops@example.org")
	tag := registerTestZSK(t, db, "example.org.")

	// Already missing from what's "served" the very first time observed.
	f := fakeDNSKEYFetcher{served: map[string]map[uint16]bool{"example.org.": {}}}
	state := make(map[string]*zoneState)

	alerts, err := checkOnce(db, fakeValidator{}, f, state)
	if err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alert on first observation, got %+v", alerts)
	}
	if state["example.org."].zskPresent[tag] {
		t.Fatalf("expected the baseline to record the key as absent")
	}
}

func TestCheckOnceAlertsWhenARegisteredZSKGoesMissing(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.", "mailto:ops@example.org")
	tag := registerTestZSK(t, db, "example.org.")

	f := fakeDNSKEYFetcher{served: map[string]map[uint16]bool{"example.org.": {tag: true}}}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, fakeValidator{}, f, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}

	f.served["example.org."] = map[uint16]bool{} // key no longer served
	alerts, err := checkOnce(db, fakeValidator{}, f, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one alert, got %+v", alerts)
	}
	a := alerts[0]
	if a.Kind != AlertZSKMissing || a.Recovered || a.KeyTag != tag {
		t.Fatalf("unexpected alert shape: %+v", a)
	}
	if len(a.Addresses) != 1 || a.Addresses[0] != "mailto:ops@example.org" {
		t.Fatalf("expected the registered contact address, got %+v", a.Addresses)
	}
}

func TestCheckOnceAlertsWhenAMissingZSKIsRestored(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")
	tag := registerTestZSK(t, db, "example.org.")

	f := fakeDNSKEYFetcher{served: map[string]map[uint16]bool{"example.org.": {}}}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, fakeValidator{}, f, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}

	f.served["example.org."] = map[uint16]bool{tag: true}
	alerts, err := checkOnce(db, fakeValidator{}, f, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Kind != AlertZSKMissing || !alerts[0].Recovered || alerts[0].KeyTag != tag {
		t.Fatalf("expected exactly one ZSK-recovered alert, got %+v", alerts)
	}
}

func TestCheckOnceZSKPresenceStaysSilentAcrossRepeatedIdenticalOutcomes(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")
	tag := registerTestZSK(t, db, "example.org.")

	f := fakeDNSKEYFetcher{served: map[string]map[uint16]bool{"example.org.": {tag: true}}}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, fakeValidator{}, f, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}
	for i := 0; i < 3; i++ {
		alerts, err := checkOnce(db, fakeValidator{}, f, state)
		if err != nil {
			t.Fatalf("checkOnce %d: %v", i, err)
		}
		if len(alerts) != 0 {
			t.Fatalf("checkOnce %d: expected no alert while the key stays present, got %+v", i, alerts)
		}
	}
}

func TestCheckOnceZSKPresenceFetchFailureSkipsSilently(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")
	tag := registerTestZSK(t, db, "example.org.")

	f := fakeDNSKEYFetcher{served: map[string]map[uint16]bool{"example.org.": {tag: true}}}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, fakeValidator{}, f, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}

	// The zone's own servers are unreachable this pass -- must not be
	// mistaken for the key having been dropped.
	f.err = map[string]error{"example.org.": fmt.Errorf("network unreachable")}
	alerts, err := checkOnce(db, fakeValidator{}, f, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alert on a fetch failure, got %+v", alerts)
	}
	if !state["example.org."].zskPresent[tag] {
		t.Fatalf("expected the last-known-good presence to be left untouched by a fetch failure")
	}
}

func TestCheckOnceZoneWithNoZSKsSkipsPresenceCheckEntirely(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")

	// A fetcher that errors for every zone -- if checkOnce tried to use
	// it for this zone (which has no ZSKs at all), this would surface as
	// a spurious problem; it must not be called in the first place.
	f := fakeDNSKEYFetcher{err: map[string]error{"example.org.": fmt.Errorf("should never be called")}}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, fakeValidator{}, f, state); err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	alerts, err := checkOnce(db, fakeValidator{}, f, state)
	if err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts for a zone with no registered ZSKs, got %+v", alerts)
	}
}

func TestCheckOnceAlertWithNoRegisteredContactStillReported(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.") // no contact registered

	v := fakeValidator{}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil {
		t.Fatalf("first checkOnce: %v", err)
	}
	v.err = map[string]error{"example.org.": fmt.Errorf("broken")}
	alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 || len(alerts[0].Addresses) != 0 {
		t.Fatalf("expected the transition still reported, with no addresses, got %+v", alerts)
	}
}
