package main

import (
	"fmt"

	"github.com/coredns/coredns/plugin/sazu"
)

// zoneState is this process's own, purely in-memory memory of whether a
// zone's chain-of-trust check last succeeded, and which of its
// registered ZSKs were last found present in the zone's live-served
// DNSKEY RRset -- the "last known good" plugin/sazu/docs/SAZU-PLAN.md's design for this
// daemon compares against. Not persisted: a restart just re-establishes
// a fresh baseline on its first pass rather than resuming exactly where
// a previous run left off. That's a deliberate simplification for this
// first cut, not an oversight -- the failure mode is narrow (a zone that
// broke and recovered entirely within one restart window goes
// unremarked) and safe (nothing is ever mis-reported, an alert is just
// possibly missed once), which is an acceptable trade for not needing
// yet another persisted table for a purely advisory monitoring signal.
type zoneState struct {
	lastOK bool

	// zskPresent tracks, per currently-registered ZSK key tag, whether
	// the last pass found it present in the zone's live-served DNSKEY
	// RRset -- so a transition (present -> missing, or the reverse) is
	// what triggers an alert, the same debounce discipline as lastOK
	// above, not a repeat alert on every pass a key stays missing. A
	// key tag that stops being registered at all (retired) simply stops
	// being looked at; its stale entry here is harmless and never
	// checked again.
	zskPresent map[uint16]bool
}

// AlertKind distinguishes what a given Alert is actually reporting --
// Notifier renders each kind with its own subject/body text (alert.go).
type AlertKind int

const (
	// AlertChainOfTrust: the zone's chain-of-trust check (parent DS
	// matching the pinned KSK) transitioned. The zero value, so every
	// existing call site that never sets Kind keeps meaning this.
	AlertChainOfTrust AlertKind = iota
	// AlertZSKMissing: a specific, currently-registered ZSK's presence
	// in the zone's live-served DNSKEY RRset transitioned -- see
	// keys.go's KeyRole doc comment (plugin/sazu) for why a dropped ZSK
	// is worth knowing about even though it never breaks chain-of-trust
	// (only the KSK is DS-anchored): a customer's own automation
	// authenticating routine pushes with a ZSK that's silently stopped
	// being served would otherwise have no way to notice.
	AlertZSKMissing
)

// Alert is one notification a check pass decided should go out: some
// per-zone check transitioned since the last pass -- either just started
// failing/missing (Recovered false) or just started passing/present
// again after having failed/been missing (Recovered true). KeyTag is
// meaningful only for AlertZSKMissing; Err only for AlertChainOfTrust
// (a missing ZSK is a comparison against a live answer, not something
// that itself produces a Go error to report).
type Alert struct {
	Zone      string
	Addresses []string
	Kind      AlertKind
	Recovered bool
	Err       error
	KeyTag    uint16
}

// checkOnce runs one pass over every zone db knows about: re-validating
// each one's chain of trust via validator exactly the way first contact
// (and a §10.4 key rollover) already does -- "does a DS matching this
// zone's pinned key exist at the parent" -- and, separately, confirming
// via dnskeys that every ZSK currently registered for the zone is still
// present in what the zone is actually serving. Returns the alerts (if
// any) that a state transition since the last pass warrants for either
// check. state is mutated in place so the next call sees this pass's
// results.
//
// A zone's very first observation (not yet in state at all) only
// establishes a baseline; it never alerts on its own, even if a check
// already fails/finds a key missing then. That's what "compares against
// last known good" means literally -- there is no "last known" yet to
// have changed from -- and avoids an alert storm at daemon startup for
// every zone already in a known, unaddressed state.
func checkOnce(db *sazu.DB, validator sazu.ChainValidator, dnskeys DNSKEYFetcher, state map[string]*zoneState) ([]Alert, error) {
	zones, err := db.ListZones()
	if err != nil {
		return nil, fmt.Errorf("listing zones: %w", err)
	}

	var alerts []Alert
	for _, zone := range zones {
		zk, ok, err := db.LoadZoneKeys(zone)
		if err != nil {
			return nil, fmt.Errorf("loading keys for %s: %w", zone, err)
		}
		if !ok {
			// Shouldn't normally happen (every zones row gets a pinned
			// key at first contact) -- nothing to check without one.
			continue
		}

		st, seen := state[zone]
		if !seen {
			st = &zoneState{}
			state[zone] = st
		}

		checkErr := validator.VerifyChainOfTrust(zone, zk.KSK.DNSKEY)
		nowOK := checkErr == nil
		switch {
		case !seen:
			// First observation: baseline only, no alert -- see doc comment.
		case st.lastOK && !nowOK:
			alerts = append(alerts, Alert{Zone: zone, Addresses: contactAddresses(db, zone), Kind: AlertChainOfTrust, Err: checkErr})
		case !st.lastOK && nowOK:
			alerts = append(alerts, Alert{Zone: zone, Addresses: contactAddresses(db, zone), Kind: AlertChainOfTrust, Recovered: true})
		}
		st.lastOK = nowOK

		if len(zk.ZSKs) > 0 {
			alerts = append(alerts, checkZSKPresence(db, zone, zk, dnskeys, st, seen)...)
		}
	}
	return alerts, nil
}

// checkZSKPresence compares zone's currently-registered ZSKs against
// what its live DNSKEY RRset actually contains, returning one alert per
// key tag whose presence transitioned since the last pass (see
// zoneState.zskPresent's doc comment for the debounce reasoning). A
// fetch failure (the zone's own servers unreachable, a transient
// network error) skips this pass's evaluation entirely, touching no
// state and raising no alert -- a brief inability to reach a zone's own
// servers is not evidence a key was dropped, and misreporting one as
// such would be strictly worse than occasionally missing a real one.
func checkZSKPresence(db *sazu.DB, zone string, zk *sazu.ZoneKeys, dnskeys DNSKEYFetcher, st *zoneState, seenBefore bool) []Alert {
	served, err := dnskeys.FetchServedDNSKEYTags(zone)
	if err != nil {
		return nil
	}
	if st.zskPresent == nil {
		st.zskPresent = make(map[uint16]bool, len(zk.ZSKs))
	}

	var alerts []Alert
	for _, zsk := range zk.ZSKs {
		tag := zsk.KeyTag()
		nowPresent := served[tag]
		wasPresent, seen := st.zskPresent[tag]
		switch {
		case !seenBefore || !seen:
			// First observation of this zone, or of this specific key
			// tag (e.g. just registered) -- baseline only, no alert.
		case wasPresent && !nowPresent:
			alerts = append(alerts, Alert{Zone: zone, Addresses: contactAddresses(db, zone), Kind: AlertZSKMissing, KeyTag: tag})
		case !wasPresent && nowPresent:
			alerts = append(alerts, Alert{Zone: zone, Addresses: contactAddresses(db, zone), Kind: AlertZSKMissing, KeyTag: tag, Recovered: true})
		}
		st.zskPresent[tag] = nowPresent
	}
	return alerts
}

// contactAddresses looks up zone's registered §10.6 contact, tolerating
// a lookup failure (or no contact registered at all) by returning no
// addresses rather than failing the whole check pass over it -- an alert
// with nothing to notify still gets logged by the caller, which is
// itself a useful signal ("this zone broke and nobody would have heard
// about it").
func contactAddresses(db *sazu.DB, zone string) []string {
	addrs, _, _ := db.LoadContact(zone)
	return addrs
}
