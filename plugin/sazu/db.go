package sazu

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	_ "modernc.org/sqlite" // pure-Go driver, registers as "sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS zones (
	origin     TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL
);

-- One row per key currently trusted for a zone: exactly one role='KSK'
-- row (first contact and every §8.2 rollover replace it, never add a
-- second) plus zero or more role='ZSK' rows (see keys.go's KeyRole doc
-- comment for what the optional ZSK split is for). can_auth_tx mirrors
-- ManagedKey.CanAuthenticateTx -- always 1 for a KSK, customer's choice
-- for a ZSK.
CREATE TABLE IF NOT EXISTS keys (
	zone        TEXT NOT NULL REFERENCES zones(origin),
	keytag      INTEGER NOT NULL,
	role        TEXT NOT NULL,
	flags       INTEGER NOT NULL,
	protocol    INTEGER NOT NULL,
	algorithm   INTEGER NOT NULL,
	public_key  TEXT NOT NULL,
	can_auth_tx INTEGER NOT NULL,
	pinned_at   INTEGER NOT NULL,
	PRIMARY KEY (zone, keytag)
);
CREATE INDEX IF NOT EXISTS keys_zone_role ON keys(zone, role);

-- §11.4 registration record: a zone's registered contact address(es),
-- newline-joined when there is more than one (see ContactUpdate/
-- splitContactOps in contact.go for the wire-side convention).
CREATE TABLE IF NOT EXISTS contacts (
	zone          TEXT PRIMARY KEY REFERENCES zones(origin),
	address       TEXT NOT NULL,
	registered_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rrs (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	zone   TEXT NOT NULL REFERENCES zones(origin),
	name   TEXT NOT NULL,
	rrtype INTEGER NOT NULL,
	rr     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rrs_zone_name_type ON rrs(zone, name, rrtype);

-- §11.5 audit trail: one row per UPDATE transaction this server decided on,
-- accepted or rejected. zone is NOT a foreign key into zones(origin) --
-- unlike every other table here, an audit entry is written for a zone
-- that was refused at first contact and so never got a zones row at all,
-- which is exactly the kind of attempt an audit trail exists to remember.
-- key_tag/key_role identify the key whose verified SIG(0) signature
-- authenticated this transaction -- both NULL when it never got that far
-- (see AuditEntry's own doc comment).
CREATE TABLE IF NOT EXISTS audit_log (
	id          TEXT PRIMARY KEY,
	zone        TEXT NOT NULL,
	remote_addr TEXT NOT NULL,
	rcode       TEXT NOT NULL,
	status      TEXT NOT NULL,
	at          INTEGER NOT NULL,
	key_tag     INTEGER,
	key_role    TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_zone_at ON audit_log(zone, at);

-- A DS-only KSK rollover waiting out its hold-down (see rollover.go):
-- at most one per zone. Any control change clears it (setVersion), in the
-- same transaction as that change.
CREATE TABLE IF NOT EXISTS pending_rollovers (
	zone         TEXT PRIMARY KEY,
	flags        INTEGER NOT NULL,
	protocol     INTEGER NOT NULL,
	algorithm    INTEGER NOT NULL,
	public_key   TEXT NOT NULL,
	requested_at INTEGER NOT NULL
);

-- Every zone's control-state version (see version.go): the counter a
-- control change must name as a prerequisite, incremented by each one.
-- Deliberately not a foreign key into zones(origin) and never deleted --
-- DeleteZone increments it instead -- so a message signed for an older
-- version can't re-create or change a decommissioned zone later.
CREATE TABLE IF NOT EXISTS zone_versions (
	zone    TEXT PRIMARY KEY,
	version INTEGER NOT NULL
);
`

// DB is SAZU's SQLite persistence backend, via modernc.org/sqlite -- a
// pure-Go driver, no cgo, keeping this in line with the rest of the tree
// (CoreDNS has no cgo dependencies; a cgo driver would affect
// cross-compilation and static builds).
//
// Store/ZoneData/KeyRegistry stay pure in-memory and untouched by this
// file -- DB is a durability layer handler.go/setup.go add on top: every
// successful UPDATE writes through to it (commit-then-apply-to-memory, so
// a persistence failure can't leave memory and disk disagreeing), and
// LoadAll hydrates memory from it once at startup. Nothing about DB is
// required: a plugin instance configured without a `db` directive keeps
// everything in memory only.
type DB struct {
	sql *sql.DB
}

// maxOpenConns bounds how many concurrent connections Open's *sql.DB pool
// will hand out. SQLite (even in WAL mode) still allows only one writer at
// a time -- this isn't an attempt to parallelize CommitUpdate itself, just
// enough headroom that a burst of concurrent zones' writes, and any reads
// (LoadZoneKeys, the audit trail) running alongside them, don't all pile
// up behind Go's own single-connection queue the way a strict
// SetMaxOpenConns(1) would. A modest, fixed cap rather than unlimited
// (0): each one is a real OS file handle, and WAL's actual concurrency
// benefit tops out long before that would matter.
const maxOpenConns = 8

// Open creates or opens a SQLite database at path and ensures its schema
// exists.
func Open(path string) (*DB, error) {
	// WAL mode lets readers (LoadZoneKeys, the audit trail) proceed
	// without waiting behind a writer and allows several connections.
	// Writers for different zones (Sazu.updateLocks serializes only per
	// zone) still take turns at SQLite's single write lock; busy_timeout
	// makes them wait up to 5s for it instead of failing with SQLITE_BUSY.
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	if _, err := sqlDB.Exec(schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("creating schema in %s: %w", path, err)
	}
	db := &DB{sql: sqlDB}
	return db, nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error { return db.sql.Close() }

// KeyChange describes a KeyRegistry mutation for CommitUpdate to persist
// alongside the rest of an UPDATE transaction, atomically -- at most one
// field is normally set per real transaction (that's what serveUpdate's
// own logic guarantees: a single push is either first contact, a KSK
// rollover, a ZSK registration, a ZSK retirement, or none of those), but
// CommitUpdate itself doesn't assume that; it just applies whichever are
// non-nil.
type KeyChange struct {
	// PinKSK is set on first contact or a successful §8.2 KSK rollover.
	PinKSK *dns.DNSKEY
	// AddZSK is set when this push registers a new optional ZSK.
	AddZSK *ManagedKey
	// RetireZSK, if non-nil, is the key tag of a ZSK this push removed.
	RetireZSK *uint16
}

// CommitUpdate persists one accepted UPDATE transactionally: optionally
// applying keyChange (pass nil for an ordinary push that changes no
// key) and applying every op in ops, all in one SQLite transaction so a
// failure partway through leaves no partial state on disk. Mirrors
// ApplyUpdateOps' RFC 2136 §2.5 classification exactly, so the two stay
// in lockstep for the same input.
func (db *DB) CommitUpdate(zone string, keyChange *KeyChange, ops []dns.RR, zclass uint16, contact *ContactUpdate) error {
	return db.CommitUpdateWithVersion(zone, nil, keyChange, ops, zclass, contact)
}

// CommitUpdateWithVersion is CommitUpdate that additionally sets the
// zone's version (see version.go) to *version, if non-nil, in the same
// transaction -- so a control change is never persisted without the
// version bump that stops it from applying a second time.
func (db *DB) CommitUpdateWithVersion(zone string, version *uint64, keyChange *KeyChange, ops []dns.RR, zclass uint16, contact *ContactUpdate) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO zones (origin, created_at) VALUES (?, ?)`, zone, now); err != nil {
		return fmt.Errorf("ensuring zone row: %w", err)
	}
	if err := setVersion(tx, zone, version); err != nil {
		return err
	}

	if keyChange != nil {
		if newKSK := keyChange.PinKSK; newKSK != nil {
			// A rollover's new KSK usually has a different key tag than
			// the one it replaces -- PRIMARY KEY (zone, keytag) would
			// leave the old row behind as a second, stale "KSK" unless
			// it's explicitly cleared first. There is always at most one
			// role='KSK' row per zone by construction, so this is safe
			// to do unconditionally.
			if _, err := tx.Exec(`DELETE FROM keys WHERE zone = ? AND role = 'KSK'`, zone); err != nil {
				return fmt.Errorf("clearing previous KSK: %w", err)
			}
			if _, err := tx.Exec(
				`INSERT INTO keys (zone, keytag, role, flags, protocol, algorithm, public_key, can_auth_tx, pinned_at)
				 VALUES (?, ?, 'KSK', ?, ?, ?, ?, 1, ?)`,
				zone, newKSK.KeyTag(), newKSK.Flags, newKSK.Protocol, newKSK.Algorithm, newKSK.PublicKey, now,
			); err != nil {
				return fmt.Errorf("pinning KSK: %w", err)
			}
		}
		if zsk := keyChange.AddZSK; zsk != nil {
			canAuth := 0
			if zsk.CanAuthenticateTx {
				canAuth = 1
			}
			if _, err := tx.Exec(
				`INSERT OR REPLACE INTO keys (zone, keytag, role, flags, protocol, algorithm, public_key, can_auth_tx, pinned_at)
				 VALUES (?, ?, 'ZSK', ?, ?, ?, ?, ?, ?)`,
				zone, zsk.KeyTag(), zsk.DNSKEY.Flags, zsk.DNSKEY.Protocol, zsk.DNSKEY.Algorithm, zsk.DNSKEY.PublicKey, canAuth, now,
			); err != nil {
				return fmt.Errorf("registering ZSK: %w", err)
			}
		}
		if keytag := keyChange.RetireZSK; keytag != nil {
			if _, err := tx.Exec(`DELETE FROM keys WHERE zone = ? AND keytag = ? AND role = 'ZSK'`, zone, *keytag); err != nil {
				return fmt.Errorf("retiring ZSK: %w", err)
			}
		}
	}

	if contact != nil {
		if len(contact.Addresses) == 0 {
			if _, err := tx.Exec(`DELETE FROM contacts WHERE zone = ?`, zone); err != nil {
				return fmt.Errorf("clearing contact: %w", err)
			}
		} else if _, err := tx.Exec(
			`INSERT OR REPLACE INTO contacts (zone, address, registered_at) VALUES (?, ?, ?)`,
			zone, strings.Join(contact.Addresses, "\n"), now,
		); err != nil {
			return fmt.Errorf("registering contact: %w", err)
		}
	}

	// A full push (one that adds the apex SOA) replaces the zone's whole
	// served content, exactly like ZoneData.PurgeContentAndApply does in
	// memory: everything except the apex DNSKEY RRset and the RRSIGs
	// covering it is dropped before this update's own records are added.
	// Without this, records a later push no longer contains -- with
	// RRSIGs still inside their validity window -- would come back on
	// the next LoadAll, along with stale NSEC/NSEC3 chains. serveUpdate
	// refuses any other kind of content change, so this is the only
	// purge a commit ever needs.
	if addsApexSOA(ops, zone, zclass) {
		if err := purgeContent(tx, zone); err != nil {
			return err
		}
	}
	// Mirrors ZoneData.dropSupersededDNSKEYSigsLocked: new signatures
	// over the apex DNSKEY RRset replace all earlier ones.
	if addsApexDNSKEYSig(ops, normalizeZone(zone), zclass) {
		if err := deleteApexRRSIGsCovering(tx, zone, dns.TypeDNSKEY); err != nil {
			return err
		}
	}

	for _, rr := range ops {
		h := rr.Header()
		switch {
		case h.Class == zclass:
			// §2.5.1 Add to an RRset. A SOA at the apex replaces any
			// existing one, mirroring ZoneData.insertLocked exactly.
			if _, ok := rr.(*dns.SOA); ok && normalizeZone(h.Name) == normalizeZone(zone) {
				if _, err := tx.Exec(`DELETE FROM rrs WHERE zone = ? AND name = ? AND rrtype = ?`,
					zone, normalizeZone(h.Name), dns.TypeSOA); err != nil {
					return fmt.Errorf("replacing SOA: %w", err)
				}
			}
			if _, err := tx.Exec(`INSERT INTO rrs (zone, name, rrtype, rr) VALUES (?, ?, ?, ?)`,
				zone, normalizeZone(h.Name), h.Rrtype, rr.String()); err != nil {
				return fmt.Errorf("adding record: %w", err)
			}
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && h.Rdlength == 0:
			// §2.5.3 Delete all RRsets from a name (apex excepted).
			if normalizeZone(h.Name) == normalizeZone(zone) {
				continue
			}
			if _, err := tx.Exec(`DELETE FROM rrs WHERE zone = ? AND name = ?`, zone, normalizeZone(h.Name)); err != nil {
				return fmt.Errorf("deleting name: %w", err)
			}
		case h.Class == dns.ClassANY && h.Rdlength == 0:
			// §2.5.2 Delete an RRset (apex SOA excepted).
			if h.Rrtype == dns.TypeSOA && normalizeZone(h.Name) == normalizeZone(zone) {
				continue
			}
			if _, err := tx.Exec(`DELETE FROM rrs WHERE zone = ? AND name = ? AND rrtype = ?`,
				zone, normalizeZone(h.Name), h.Rrtype); err != nil {
				return fmt.Errorf("deleting rrset: %w", err)
			}
		case h.Class == dns.ClassNONE:
			// §2.5.4 Delete one RR -- fetch candidates and match by
			// content (ignoring TTL/Class) the same way ZoneData.DeleteRR
			// does, since matching that in SQL would need the same
			// normalization logic duplicated as a query.
			rows, err := tx.Query(`SELECT id, rr FROM rrs WHERE zone = ? AND name = ? AND rrtype = ?`,
				zone, normalizeZone(h.Name), h.Rrtype)
			if err != nil {
				return fmt.Errorf("finding record to delete: %w", err)
			}
			var toDelete []int64
			for rows.Next() {
				var id int64
				var text string
				if err := rows.Scan(&id, &text); err != nil {
					rows.Close()
					return err
				}
				existing, err := dns.NewRR(text)
				if err != nil {
					continue // shouldn't happen; skip rather than fail the whole transaction
				}
				if rrEqualContent(existing, rr) {
					toDelete = append(toDelete, id)
				}
			}
			rows.Close()
			for _, id := range toDelete {
				if _, err := tx.Exec(`DELETE FROM rrs WHERE id = ?`, id); err != nil {
					return fmt.Errorf("deleting record: %w", err)
				}
			}
		default:
			return fmt.Errorf("malformed update op for %s", h.Name)
		}
	}

	return tx.Commit()
}

// addsApexSOA reports whether ops adds a SOA at zone's apex. Unlike
// containsAPEXSOA it goes by class alone (an add carries the zone's
// class; RFC 2136 deletes carry ANY or NONE), not Rdlength, so it also
// holds for records built in Go rather than unpacked from the wire.
func addsApexSOA(ops []dns.RR, zone string, zclass uint16) bool {
	for _, rr := range ops {
		if _, ok := rr.(*dns.SOA); ok && rr.Header().Class == zclass && normalizeZone(rr.Header().Name) == normalizeZone(zone) {
			return true
		}
	}
	return false
}

// purgeContent deletes every stored record for zone except the apex
// DNSKEY RRset and the RRSIGs covering it -- the on-disk counterpart of
// ZoneData.purgeContentLocked.
func purgeContent(tx *sql.Tx, zone string) error {
	apex := normalizeZone(zone)
	if _, err := tx.Exec(`DELETE FROM rrs WHERE zone = ? AND NOT (name = ? AND rrtype IN (?, ?))`,
		zone, apex, dns.TypeDNSKEY, dns.TypeRRSIG); err != nil {
		return fmt.Errorf("purging zone content: %w", err)
	}
	rows, err := tx.Query(`SELECT id, rr FROM rrs WHERE zone = ? AND name = ? AND rrtype = ?`, zone, apex, dns.TypeRRSIG)
	if err != nil {
		return fmt.Errorf("finding apex RRSIGs to purge: %w", err)
	}
	var stale []int64
	for rows.Next() {
		var id int64
		var text string
		if err := rows.Scan(&id, &text); err != nil {
			rows.Close()
			return err
		}
		rr, err := dns.NewRR(text)
		if sig, ok := rr.(*dns.RRSIG); err != nil || !ok || sig.TypeCovered != dns.TypeDNSKEY {
			stale = append(stale, id)
		}
	}
	rows.Close()
	for _, id := range stale {
		if _, err := tx.Exec(`DELETE FROM rrs WHERE id = ?`, id); err != nil {
			return fmt.Errorf("purging apex RRSIG: %w", err)
		}
	}
	return nil
}

// deleteApexRRSIGsCovering deletes every stored RRSIG at zone's apex
// that covers covered.
func deleteApexRRSIGsCovering(tx *sql.Tx, zone string, covered uint16) error {
	apex := normalizeZone(zone)
	rows, err := tx.Query(`SELECT id, rr FROM rrs WHERE zone = ? AND name = ? AND rrtype = ?`, zone, apex, dns.TypeRRSIG)
	if err != nil {
		return fmt.Errorf("finding apex RRSIGs: %w", err)
	}
	var stale []int64
	for rows.Next() {
		var id int64
		var text string
		if err := rows.Scan(&id, &text); err != nil {
			rows.Close()
			return err
		}
		if rr, err := dns.NewRR(text); err == nil {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == covered {
				stale = append(stale, id)
			}
		}
	}
	rows.Close()
	for _, id := range stale {
		if _, err := tx.Exec(`DELETE FROM rrs WHERE id = ?`, id); err != nil {
			return fmt.Errorf("deleting superseded RRSIG: %w", err)
		}
	}
	return nil
}

// setVersion upserts zone's version -- and, since only a control
// change ever sets it, cancels any pending KSK rollover for the zone in
// the same transaction (see rollover.go). A nil version is a no-op.
func setVersion(tx *sql.Tx, zone string, version *uint64) error {
	if version == nil {
		return nil
	}
	if _, err := tx.Exec(`DELETE FROM pending_rollovers WHERE zone = ?`, normalizeZone(zone)); err != nil {
		return fmt.Errorf("clearing pending rollover: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO zone_versions (zone, version) VALUES (?, ?)
		 ON CONFLICT(zone) DO UPDATE SET version = excluded.version`,
		normalizeZone(zone), int64(*version)); err != nil {
		return fmt.Errorf("recording zone version: %w", err)
	}
	return nil
}

// SetPendingRollover records zone's pending DS-only KSK rollover,
// replacing any other.
func (db *DB) SetPendingRollover(zone string, pr PendingRollover) error {
	_, err := db.sql.Exec(
		`INSERT INTO pending_rollovers (zone, flags, protocol, algorithm, public_key, requested_at) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(zone) DO UPDATE SET flags = excluded.flags, protocol = excluded.protocol,
		   algorithm = excluded.algorithm, public_key = excluded.public_key, requested_at = excluded.requested_at`,
		normalizeZone(zone), pr.KSK.Flags, pr.KSK.Protocol, pr.KSK.Algorithm, pr.KSK.PublicKey, pr.RequestedAt.Unix())
	if err != nil {
		return fmt.Errorf("recording pending rollover: %w", err)
	}
	return nil
}

// LoadPendingRollovers returns every persisted pending rollover, by zone.
func (db *DB) LoadPendingRollovers() (map[string]PendingRollover, error) {
	rows, err := db.sql.Query(`SELECT zone, flags, protocol, algorithm, public_key, requested_at FROM pending_rollovers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]PendingRollover)
	for rows.Next() {
		var zone, pub string
		var flags, protocol, algorithm int
		var at int64
		if err := rows.Scan(&zone, &flags, &protocol, &algorithm, &pub, &at); err != nil {
			return nil, err
		}
		out[zone] = PendingRollover{
			KSK: &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags: uint16(flags), Protocol: uint8(protocol), Algorithm: uint8(algorithm), PublicKey: pub},
			RequestedAt: time.Unix(at, 0),
		}
	}
	return out, rows.Err()
}

// LoadVersions returns every persisted zone version, for seeding a
// VersionRegistry at startup.
func (db *DB) LoadVersions() (map[string]uint64, error) {
	rows, err := db.sql.Query(`SELECT zone, version FROM zone_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]uint64)
	for rows.Next() {
		var zone string
		var v int64
		if err := rows.Scan(&zone, &v); err != nil {
			return nil, err
		}
		out[zone] = uint64(v)
	}
	return out, rows.Err()
}

// EarliestRRSIGExpiration returns the soonest expiration among every
// RRSIG stored for zone -- the moment the zone starts failing
// validation if its owner stops re-pushing, since this server never
// re-signs anything itself. ok is false when the zone has no RRSIGs.
func (db *DB) EarliestRRSIGExpiration(zone string) (earliest time.Time, ok bool, err error) {
	rows, err := db.sql.Query(`SELECT rr FROM rrs WHERE zone = ? AND rrtype = ?`, normalizeZone(zone), dns.TypeRRSIG)
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var text string
		if err := rows.Scan(&text); err != nil {
			return time.Time{}, false, err
		}
		rr, err := dns.NewRR(text)
		sig, isSig := rr.(*dns.RRSIG)
		if err != nil || !isSig {
			continue
		}
		exp := time.Unix(int64(sig.Expiration), 0)
		if !ok || exp.Before(earliest) {
			earliest, ok = exp, true
		}
	}
	return earliest, ok, rows.Err()
}

// DeleteZone removes every persisted trace of zone -- its zones row,
// every keys row, every rrs row, and its contacts row, if any -- so a
// subsequent LoadAll sees no trace of it. Deliberately never touches
// audit_log: a decommissioned zone's transaction history (including the
// decommission transaction itself) stays available for an operator
// investigating "what happened to this zone," the same reason audit_log
// was never a foreign key against zones(origin) to begin with -- it
// already has to survive a zone existing only briefly, or never having
// existed at all (a rejected first-contact attempt), let alone one that
// existed and was later removed.
func (db *DB) DeleteZone(zone string) error {
	return db.deleteZone(zone, nil)
}

// DeleteZoneWithVersion is DeleteZone that also sets the zone's version
// (which survives the zone -- see zone_versions) in the same
// transaction.
func (db *DB) DeleteZoneWithVersion(zone string, version uint64) error {
	return db.deleteZone(zone, &version)
}

func (db *DB) deleteZone(zone string, version *uint64) error {
	zone = normalizeZone(zone)
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit
	if err := setVersion(tx, zone, version); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM rrs WHERE zone = ?`, zone); err != nil {
		return fmt.Errorf("deleting rrs: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM keys WHERE zone = ?`, zone); err != nil {
		return fmt.Errorf("deleting keys: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM contacts WHERE zone = ?`, zone); err != nil {
		return fmt.Errorf("deleting contact: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM zones WHERE origin = ?`, zone); err != nil {
		return fmt.Errorf("deleting zone: %w", err)
	}
	return tx.Commit()
}

// LoadAll reads every persisted zone, key, and registered contact back
// into fresh in-memory Store/KeyRegistry/ContactRegistry instances, for
// hydrating a plugin instance at startup.
func (db *DB) LoadAll() (*Store, *KeyRegistry, *ContactRegistry, error) {
	store := NewStore()
	keys := NewKeyRegistry()
	contacts := NewContactRegistry()

	origins, err := db.ListZones()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading zones: %w", err)
	}

	for _, origin := range origins {
		z := store.GetOrCreate(origin)

		rrRows, err := db.sql.Query(`SELECT rr FROM rrs WHERE zone = ? ORDER BY id ASC`, origin)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("loading records for %s: %w", origin, err)
		}
		for rrRows.Next() {
			var text string
			if err := rrRows.Scan(&text); err != nil {
				rrRows.Close()
				return nil, nil, nil, err
			}
			rr, err := dns.NewRR(text)
			if err != nil {
				rrRows.Close()
				return nil, nil, nil, fmt.Errorf("parsing stored record %q for %s: %w", text, origin, err)
			}
			z.Insert(rr)
		}
		rrRows.Close()

		switch zk, ok, err := db.LoadZoneKeys(origin); {
		case err != nil:
			return nil, nil, nil, fmt.Errorf("loading keys for %s: %w", origin, err)
		case ok:
			keys.PinKSK(origin, zk.KSK.DNSKEY)
			for _, zsk := range zk.ZSKs {
				if err := keys.AddZSK(origin, zsk.DNSKEY, zsk.CanAuthenticateTx); err != nil {
					return nil, nil, nil, fmt.Errorf("restoring ZSK for %s: %w", origin, err)
				}
			}
		default:
			// A zone row with no pinned key shouldn't normally happen
			// (CommitUpdate always pins one at first contact), but isn't
			// fatal to loading -- the zone just won't accept further
			// pushes until an operator intervenes.
		}

		switch addrs, ok, err := db.LoadContact(origin); {
		case err != nil:
			return nil, nil, nil, fmt.Errorf("loading contact for %s: %w", origin, err)
		case ok:
			contacts.Set(origin, addrs)
		default:
			// No contact registered for this zone -- fine, §11.4 is optional.
		}
	}

	return store, keys, contacts, nil
}

// ListZones returns every onboarded zone's origin -- a lighter-weight
// alternative to LoadAll for a caller (like sazu-watchd, §11.4) that needs
// to enumerate zones without loading their full content.
func (db *DB) ListZones() ([]string, error) {
	rows, err := db.sql.Query(`SELECT origin FROM zones`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var origins []string
	for rows.Next() {
		var origin string
		if err := rows.Scan(&origin); err != nil {
			return nil, err
		}
		origins = append(origins, origin)
	}
	return origins, rows.Err()
}

// LoadKey returns zone's KSK, if any -- a lighter-weight alternative to
// LoadAll/LoadZoneKeys for a caller (like sazu-watchd, §11.4) that only
// needs the one key its chain-of-trust re-check actually cares about:
// a ZSK is never DS-anchored, so it has nothing for that check to verify
// in the first place.
func (db *DB) LoadKey(zone string) (*dns.DNSKEY, bool, error) {
	var flags, protocol, algorithm int64
	var publicKey string
	switch err := db.sql.QueryRow(`SELECT flags, protocol, algorithm, public_key FROM keys WHERE zone = ? AND role = 'KSK'`, zone).
		Scan(&flags, &protocol, &algorithm, &publicKey); err {
	case nil:
		return &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
			Flags:     uint16(flags),
			Protocol:  uint8(protocol),
			Algorithm: uint8(algorithm),
			PublicKey: publicKey,
		}, true, nil
	case sql.ErrNoRows:
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// LoadZoneKeys returns zone's full key set -- its KSK plus every
// registered ZSK -- for hydrating a KeyRegistry (LoadAll) or for a
// caller that needs more than LoadKey's KSK-only view.
func (db *DB) LoadZoneKeys(zone string) (*ZoneKeys, bool, error) {
	rows, err := db.sql.Query(
		`SELECT keytag, role, flags, protocol, algorithm, public_key, can_auth_tx FROM keys WHERE zone = ?`, zone)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	zk := &ZoneKeys{}
	for rows.Next() {
		var keytag int64
		var role string
		var flags, protocol, algorithm, canAuth int64
		var publicKey string
		if err := rows.Scan(&keytag, &role, &flags, &protocol, &algorithm, &publicKey, &canAuth); err != nil {
			return nil, false, err
		}
		dnskey := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
			Flags:     uint16(flags),
			Protocol:  uint8(protocol),
			Algorithm: uint8(algorithm),
			PublicKey: publicKey,
		}
		switch role {
		case "KSK":
			zk.KSK = &ManagedKey{DNSKEY: dnskey, Role: RoleKSK, CanAuthenticateTx: true}
		case "ZSK":
			zk.ZSKs = append(zk.ZSKs, &ManagedKey{DNSKEY: dnskey, Role: RoleZSK, CanAuthenticateTx: canAuth != 0})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if zk.KSK == nil {
		return nil, false, nil
	}
	return zk, true, nil
}

// LoadContact returns the registered §11.4 contact addresses for zone, if
// any -- a lighter-weight alternative to LoadAll for a caller that only
// needs one zone's contact.
func (db *DB) LoadContact(zone string) ([]string, bool, error) {
	var address string
	switch err := db.sql.QueryRow(`SELECT address FROM contacts WHERE zone = ?`, zone).Scan(&address); err {
	case nil:
		return strings.Split(address, "\n"), true, nil
	case sql.ErrNoRows:
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// RecordTransaction appends one row to the §11.5 audit trail: entry.ID must
// be unique (it's the primary key), which newTransactionID's randomness
// already guarantees in practice. A write here is independent of, and
// never rolled back by, CommitUpdate's own transaction -- the audit
// record is written by the caller (serveUpdate) after that transaction
// has already succeeded or failed, and is deliberately never itself the
// reason an UPDATE fails: see handler.go's own comment where this is
// called for why a logging error here only gets logged, not surfaced to
// the client.
func (db *DB) RecordTransaction(entry AuditEntry) error {
	_, err := db.sql.Exec(
		`INSERT INTO audit_log (id, zone, remote_addr, rcode, status, at, key_tag, key_role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.Zone, entry.RemoteAddr, entry.Rcode, entry.Status, entry.At.Unix(), entry.KeyTag, nullIfEmpty(entry.KeyRole),
	)
	return err
}

// nullIfEmpty maps "" to a real SQL NULL rather than storing it as a
// zero-length string -- used for AuditEntry.KeyRole, which is only ever
// "" in step with KeyTag being nil (see AuditEntry's doc comment), so
// the two columns stay symmetric: both NULL, or both set.
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RecentTransactions returns up to limit audit-log entries for zone,
// newest first -- the read side of the §11.5 audit trail, for an operator
// (or a future admin surface) asking "what happened to this zone's
// pushes recently."
func (db *DB) RecentTransactions(zone string, limit int) ([]AuditEntry, error) {
	rows, err := db.sql.Query(
		`SELECT id, zone, remote_addr, rcode, status, at, key_tag, key_role FROM audit_log WHERE zone = ? ORDER BY at DESC, rowid DESC LIMIT ?`,
		zone, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		var keyTag sql.NullInt64
		var keyRole sql.NullString
		if err := rows.Scan(&e.ID, &e.Zone, &e.RemoteAddr, &e.Rcode, &e.Status, &at, &keyTag, &keyRole); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0)
		if keyTag.Valid {
			tag := uint16(keyTag.Int64)
			e.KeyTag = &tag
		}
		e.KeyRole = keyRole.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
