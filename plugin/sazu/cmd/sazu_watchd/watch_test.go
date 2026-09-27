package main

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

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
	if early, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil || len(early) != 0 {
		t.Fatalf("expected no alert after a single differing pass (debounce), got %+v (%v)", early, err)
	}
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
	if early, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil || len(early) != 0 {
		t.Fatalf("expected no alert after a single differing pass (debounce), got %+v (%v)", early, err)
	}
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
	if early, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil || len(early) != 0 {
		t.Fatalf("expected no alert after a single differing pass (debounce), got %+v (%v)", early, err)
	}
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
	if early, err := checkOnce(db, fakeValidator{}, f, state); err != nil || len(early) != 0 {
		t.Fatalf("expected no alert after a single differing pass (debounce), got %+v (%v)", early, err)
	}
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
	if early, err := checkOnce(db, fakeValidator{}, f, state); err != nil || len(early) != 0 {
		t.Fatalf("expected no alert after a single differing pass (debounce), got %+v (%v)", early, err)
	}
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
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil { // debounce: first differing pass
		t.Fatal(err)
	}
	alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
	if err != nil {
		t.Fatalf("second checkOnce: %v", err)
	}
	if len(alerts) != 1 || len(alerts[0].Addresses) != 0 {
		t.Fatalf("expected the transition still reported, with no addresses, got %+v", alerts)
	}
}

// commitSignedSOA stores a SOA plus an RRSIG over it expiring at expires
// -- enough for checkSignatureExpiry, which only reads expirations.
func commitSignedSOA(t *testing.T, db *sazu.DB, zone string, serial uint32, expires time.Time) {
	t.Helper()
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns: "ns1." + dns.Fqdn(zone), Mbox: "hostmaster." + dns.Fqdn(zone), Serial: serial, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 3600}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeSOA, Algorithm: dns.ED25519, Labels: 2, OrigTtl: 3600, KeyTag: 1, SignerName: dns.Fqdn(zone),
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(expires.Unix()), Signature: "AAAA"}
	if err := db.CommitUpdate(zone, nil, []dns.RR{soa, sig}, dns.ClassINET, nil); err != nil {
		t.Fatalf("CommitUpdate: %v", err)
	}
}

// TestCheckOnceWarnsBeforeSignaturesExpire: a zone whose earliest RRSIG
// expires within the warning window alerts immediately -- even on the
// first pass, since a deadline has no baseline to establish -- stays
// quiet while nothing changes, and recovers once a fresh push moves the
// expiration out again.
func TestCheckOnceWarnsBeforeSignaturesExpire(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.", "mailto:ops@example.org")
	soon := time.Now().Add(2 * 24 * time.Hour)
	commitSignedSOA(t, db, "example.org.", 2, soon)

	state := make(map[string]*zoneState)
	validator := fakeValidator{}
	fetcher := fakeDNSKEYFetcher{}

	expiryAlerts := func() []Alert {
		t.Helper()
		alerts, err := checkOnce(db, validator, fetcher, state)
		if err != nil {
			t.Fatalf("checkOnce: %v", err)
		}
		var out []Alert
		for _, a := range alerts {
			if a.Kind == AlertSignatureExpiry {
				out = append(out, a)
			}
		}
		return out
	}

	first := expiryAlerts()
	if len(first) != 1 || first[0].Recovered || first[0].Expires.Unix() != soon.Unix() {
		t.Fatalf("expected one expiry warning on the first pass, got %+v", first)
	}
	if len(first[0].Addresses) != 1 {
		t.Fatalf("expected the warning to go to the registered contact, got %v", first[0].Addresses)
	}
	if again := expiryAlerts(); len(again) != 0 {
		t.Fatalf("expected no repeat warning while nothing changed, got %+v", again)
	}

	commitSignedSOA(t, db, "example.org.", 3, time.Now().Add(30*24*time.Hour))
	recovered := expiryAlerts()
	if len(recovered) != 1 || !recovered[0].Recovered {
		t.Fatalf("expected a recovery once signatures were refreshed, got %+v", recovered)
	}
}

// TestCheckOnceNoExpiryWarningForFreshSignatures: nothing to say about a
// zone well outside the window, first pass included.
func TestCheckOnceNoExpiryWarningForFreshSignatures(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")
	commitSignedSOA(t, db, "example.org.", 2, time.Now().Add(30*24*time.Hour))
	alerts, err := checkOnce(db, fakeValidator{}, fakeDNSKEYFetcher{}, make(map[string]*zoneState))
	if err != nil {
		t.Fatalf("checkOnce: %v", err)
	}
	for _, a := range alerts {
		if a.Kind == AlertSignatureExpiry {
			t.Fatalf("expected no expiry warning, got %+v", a)
		}
	}
}

// TestCheckOnceAlertsOnPendingRollover: a pending rollover alerts right
// away -- first pass included -- and recovers once it's gone.
func TestCheckOnceAlertsOnPendingRollover(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.", "mailto:ops@example.org")
	newKSK, _, err := sazu.GenerateEd25519Key("example.org.", true)
	if err != nil {
		t.Fatal(err)
	}
	requested := time.Now().Truncate(time.Second)
	if err := db.SetPendingRollover("example.org.", sazu.PendingRollover{KSK: newKSK, RequestedAt: requested}); err != nil {
		t.Fatal(err)
	}
	state := make(map[string]*zoneState)
	pendingAlerts := func() []Alert {
		t.Helper()
		alerts, err := checkOnce(db, fakeValidator{}, fakeDNSKEYFetcher{}, state)
		if err != nil {
			t.Fatalf("checkOnce: %v", err)
		}
		var out []Alert
		for _, a := range alerts {
			if a.Kind == AlertRolloverPending {
				out = append(out, a)
			}
		}
		return out
	}

	first := pendingAlerts()
	if len(first) != 1 || first[0].Recovered || first[0].KeyTag != newKSK.KeyTag() || !first[0].Expires.Equal(requested) {
		t.Fatalf("expected one pending-rollover alert on the first pass, got %+v", first)
	}
	if again := pendingAlerts(); len(again) != 0 {
		t.Fatalf("expected no repeat alert, got %+v", again)
	}
	// Any control change clears it; a version bump is the simplest.
	v := uint64(5)
	if err := db.CommitUpdateWithVersion("example.org.", &v, nil, nil, dns.ClassINET, nil); err != nil {
		t.Fatal(err)
	}
	if rec := pendingAlerts(); len(rec) != 1 || !rec[0].Recovered {
		t.Fatalf("expected a recovery once it's no longer pending, got %+v", rec)
	}
}

// TestCheckOnceTreatsUnreachableParentAsInconclusive: a pass that can't
// reach the parent at all neither alerts nor counts towards the debounce.
func TestCheckOnceTreatsUnreachableParentAsInconclusive(t *testing.T) {
	db := openTestDB(t)
	onboardTestZone(t, db, "example.org.")
	v := fakeValidator{}
	state := make(map[string]*zoneState)
	if _, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state); err != nil {
		t.Fatal(err)
	}
	v.err = map[string]error{"example.org.": &sazu.ChainError{Op: "query", Msg: "timeout"}}
	for i := 0; i < 3; i++ {
		alerts, err := checkOnce(db, v, fakeDNSKEYFetcher{}, state)
		if err != nil || len(alerts) != 0 {
			t.Fatalf("pass %d: expected no alert for an unreachable parent, got %+v (%v)", i, alerts, err)
		}
	}
	if !state["example.org."].lastOK {
		t.Fatalf("an unreachable parent must not change the last known outcome")
	}
}
