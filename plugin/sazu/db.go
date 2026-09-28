package sazu

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
)

// DB persists SAZU's state in a bbolt database, the embedded store CoreDNS
// already uses (plugin/dynupdate). The in-memory Store, KeyRegistry and
// registries are what the plugin works with; DB is written through on
// every accepted update, before memory changes, and read once at startup.
//
// bbolt lets only one process hold a database file open for writing, and
// sazu-watchd reads the same file from its own process. So DB never keeps
// the file open: each operation opens it, runs one transaction and closes
// it, and bbolt's file lock (with a timeout) makes the two processes take
// turns. Within a process, operations on one file are serialized.
type DB struct {
	path     string
	readOnly bool
}

// Buckets. Keys are zone origins unless noted.
var (
	bucketZones    = []byte("zones")    // -> creation time, 8 bytes big-endian unix seconds
	bucketRecords  = []byte("records")  // -> the zone's records, wire format (encodeRecords)
	bucketKeys     = []byte("keys")     // -> storedKeys, JSON
	bucketContacts = []byte("contacts") // -> storedContact, JSON
	bucketVersions = []byte("versions") // -> the zone version, 8 bytes big-endian
	bucketPending  = []byte("pending")  // -> storedPending, JSON
	// bucketAudit is keyed by zone, 0x00, the time as 8 bytes big-endian
	// unix nanoseconds, then the transaction ID, so one zone's entries are
	// contiguous and in time order.
	bucketAudit = []byte("audit")
)

var allBuckets = [][]byte{bucketZones, bucketRecords, bucketKeys, bucketContacts, bucketVersions, bucketPending, bucketAudit}

// dbLockTimeout bounds how long an operation waits for the other process
// (CoreDNS or sazu-watchd) to finish with the file.
const dbLockTimeout = 10 * time.Second

var (
	dbFileMu    sync.Mutex
	dbFileLocks = map[string]*sync.Mutex{}
)

func fileLock(path string) *sync.Mutex {
	dbFileMu.Lock()
	defer dbFileMu.Unlock()
	mu, ok := dbFileLocks[path]
	if !ok {
		mu = new(sync.Mutex)
		dbFileLocks[path] = mu
	}
	return mu
}

// Open returns the database at path, creating it if it doesn't exist.
func Open(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	db := &DB{path: abs}
	if err := db.update(func(*bolt.Tx) error { return nil }); err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return db, nil
}

// OpenReadOnly returns the existing database at path for reading only.
func OpenReadOnly(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, err
	}
	return &DB{path: abs, readOnly: true}, nil
}

// Close is a no-op: DB holds no open file between operations.
func (db *DB) Close() error { return nil }

// Path returns the database file's absolute path.
func (db *DB) Path() string { return db.path }

func (db *DB) run(write bool, fn func(*bolt.Tx) error) error {
	mu := fileLock(db.path)
	mu.Lock()
	defer mu.Unlock()
	b, err := bolt.Open(db.path, 0o600, &bolt.Options{Timeout: dbLockTimeout, ReadOnly: !write})
	if err != nil {
		return err
	}
	defer b.Close()
	if !write {
		return b.View(fn)
	}
	return b.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

func (db *DB) update(fn func(*bolt.Tx) error) error {
	if db.readOnly {
		return errors.New("database opened read-only")
	}
	return db.run(true, fn)
}

func (db *DB) view(fn func(*bolt.Tx) error) error { return db.run(false, fn) }

// bucket returns name from tx, or nil in a read-only transaction on a
// database that doesn't have it yet.
func bucket(tx *bolt.Tx, name []byte) *bolt.Bucket { return tx.Bucket(name) }

// KeyChange describes a KeyRegistry mutation for CommitUpdate to persist
// alongside the rest of an UPDATE transaction, atomically. CommitUpdate
// applies whichever fields are set.
type KeyChange struct {
	// PinKSK is set on first contact or a successful §8.2 KSK rollover.
	PinKSK *dns.DNSKEY
	// AddZSK is set when this push registers a new ZSK.
	AddZSK *ManagedKey
	// RetireZSK, if non-nil, is the key tag of a ZSK this push removed.
	RetireZSK *uint16
}

type storedKey struct {
	DNSKEY            string `json:"dnskey"`
	CanAuthenticateTx bool   `json:"can_auth_tx"`
}

type storedKeys struct {
	KSK  storedKey   `json:"ksk"`
	ZSKs []storedKey `json:"zsks,omitempty"`
}

type storedContact struct {
	Addresses    []string  `json:"addresses"`
	RegisteredAt time.Time `json:"registered_at"`
}

type storedPending struct {
	DNSKEY      string    `json:"dnskey"`
	RequestedAt time.Time `json:"requested_at"`
}

// CommitUpdate persists one accepted UPDATE in a single transaction:
// keyChange (nil for none), the update ops applied to the zone's stored
// records exactly as ZoneData applies them in memory, and contact.
func (db *DB) CommitUpdate(zone string, keyChange *KeyChange, ops []dns.RR, zclass uint16, contact *ContactUpdate) error {
	return db.CommitUpdateWithVersion(zone, nil, keyChange, ops, zclass, contact)
}

// CommitUpdateWithVersion is CommitUpdate that also sets the zone's
// version (see version.go) to *version, if non-nil, in the same
// transaction, so a control change is never persisted without the version
// bump that stops it from applying twice.
func (db *DB) CommitUpdateWithVersion(zone string, version *uint64, keyChange *KeyChange, ops []dns.RR, zclass uint16, contact *ContactUpdate) error {
	zone = normalizeZone(zone)
	key := []byte(zone)
	return db.update(func(tx *bolt.Tx) error {
		zones := tx.Bucket(bucketZones)
		if zones.Get(key) == nil {
			if err := zones.Put(key, u64(uint64(time.Now().Unix()))); err != nil {
				return err
			}
		}
		if err := setVersion(tx, zone, version); err != nil {
			return err
		}
		if keyChange != nil {
			if err := applyKeyChange(tx.Bucket(bucketKeys), key, keyChange); err != nil {
				return err
			}
		}
		if contact != nil {
			contacts := tx.Bucket(bucketContacts)
			if len(contact.Addresses) == 0 {
				if err := contacts.Delete(key); err != nil {
					return err
				}
			} else if err := putJSON(contacts, key, storedContact{Addresses: contact.Addresses, RegisteredAt: time.Now()}); err != nil {
				return err
			}
		}
		if len(ops) == 0 {
			return nil
		}

		// Apply the ops with the same code the in-memory zone uses.
		records := tx.Bucket(bucketRecords)
		stored, err := decodeRecords(records.Get(key))
		if err != nil {
			return fmt.Errorf("stored records for %s: %w", zone, err)
		}
		z := NewZoneData(zone)
		for _, rr := range stored {
			z.Insert(rr)
		}
		if addsApexSOA(ops, zone, zclass) {
			err = z.PurgeContentAndApply(ops, zclass)
		} else {
			err = z.ApplyOps(ops, zclass)
		}
		if err != nil {
			return err
		}
		enc, err := encodeRecords(z.Records())
		if err != nil {
			return err
		}
		return records.Put(key, enc)
	})
}

func applyKeyChange(keys *bolt.Bucket, key []byte, kc *KeyChange) error {
	var sk storedKeys
	if v := keys.Get(key); v != nil {
		if err := json.Unmarshal(v, &sk); err != nil {
			return err
		}
	}
	if kc.PinKSK != nil {
		sk.KSK = storedKey{DNSKEY: kc.PinKSK.String(), CanAuthenticateTx: true}
	}
	if kc.AddZSK != nil {
		zsk := storedKey{DNSKEY: kc.AddZSK.DNSKEY.String(), CanAuthenticateTx: kc.AddZSK.CanAuthenticateTx}
		replaced := false
		for i, k := range sk.ZSKs {
			if dnskeyFromText(k.DNSKEY).KeyTag() == kc.AddZSK.KeyTag() {
				sk.ZSKs[i], replaced = zsk, true
			}
		}
		if !replaced {
			sk.ZSKs = append(sk.ZSKs, zsk)
		}
	}
	if kc.RetireZSK != nil {
		kept := sk.ZSKs[:0]
		for _, k := range sk.ZSKs {
			if dnskeyFromText(k.DNSKEY).KeyTag() != *kc.RetireZSK {
				kept = append(kept, k)
			}
		}
		sk.ZSKs = kept
	}
	return putJSON(keys, key, sk)
}

// addsApexSOA reports whether ops adds a SOA at zone's apex. It goes by
// class alone (an add carries the zone's class; RFC 2136 deletes carry ANY
// or NONE), not Rdlength, so it also holds for records built in Go rather
// than unpacked from the wire.
func addsApexSOA(ops []dns.RR, zone string, zclass uint16) bool {
	for _, rr := range ops {
		if _, ok := rr.(*dns.SOA); ok && rr.Header().Class == zclass && normalizeZone(rr.Header().Name) == normalizeZone(zone) {
			return true
		}
	}
	return false
}

// setVersion stores zone's version and, since only a control change sets
// it, cancels any pending KSK rollover for the zone in the same
// transaction (see rollover.go). A nil version is a no-op.
func setVersion(tx *bolt.Tx, zone string, version *uint64) error {
	if version == nil {
		return nil
	}
	key := []byte(normalizeZone(zone))
	if err := tx.Bucket(bucketPending).Delete(key); err != nil {
		return err
	}
	return tx.Bucket(bucketVersions).Put(key, u64(*version))
}

// SetPendingRollover records zone's pending DS-only KSK rollover,
// replacing any other.
func (db *DB) SetPendingRollover(zone string, pr PendingRollover) error {
	return db.update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketPending), []byte(normalizeZone(zone)),
			storedPending{DNSKEY: pr.KSK.String(), RequestedAt: pr.RequestedAt})
	})
}

// LoadPendingRollovers returns every persisted pending rollover, by zone.
func (db *DB) LoadPendingRollovers() (map[string]PendingRollover, error) {
	out := make(map[string]PendingRollover)
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketPending)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var sp storedPending
			if err := json.Unmarshal(v, &sp); err != nil {
				return err
			}
			out[string(k)] = PendingRollover{KSK: dnskeyFromText(sp.DNSKEY), RequestedAt: sp.RequestedAt}
			return nil
		})
	})
	return out, err
}

// LoadVersions returns every persisted zone version, for seeding a
// VersionRegistry at startup.
func (db *DB) LoadVersions() (map[string]uint64, error) {
	out := make(map[string]uint64)
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketVersions)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			out[string(k)] = binary.BigEndian.Uint64(v)
			return nil
		})
	})
	return out, err
}

// EarliestRRSIGExpiration returns the soonest expiration among zone's
// stored RRSIGs: when the zone starts failing validation if its owner
// stops pushing, since the server never re-signs. ok is false when the
// zone has no RRSIGs.
func (db *DB) EarliestRRSIGExpiration(zone string) (earliest time.Time, ok bool, err error) {
	records, err := db.zoneRecords(zone)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, rr := range records {
		sig, isSig := rr.(*dns.RRSIG)
		if !isSig {
			continue
		}
		exp := time.Unix(int64(sig.Expiration), 0)
		if !ok || exp.Before(earliest) {
			earliest, ok = exp, true
		}
	}
	return earliest, ok, nil
}

func (db *DB) zoneRecords(zone string) ([]dns.RR, error) {
	var records []dns.RR
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketRecords)
		if b == nil {
			return nil
		}
		var err error
		records, err = decodeRecords(b.Get([]byte(normalizeZone(zone))))
		return err
	})
	return records, err
}

// DeleteZone removes zone's records, keys, contact and pending rollover.
// The audit trail is kept, so what happened to a removed zone can still be
// looked up, and so is its version (see version.go).
func (db *DB) DeleteZone(zone string) error {
	return db.deleteZone(zone, nil)
}

// DeleteZoneWithVersion is DeleteZone that also sets the zone's version in
// the same transaction.
func (db *DB) DeleteZoneWithVersion(zone string, version uint64) error {
	return db.deleteZone(zone, &version)
}

func (db *DB) deleteZone(zone string, version *uint64) error {
	zone = normalizeZone(zone)
	key := []byte(zone)
	return db.update(func(tx *bolt.Tx) error {
		if err := setVersion(tx, zone, version); err != nil {
			return err
		}
		for _, name := range [][]byte{bucketZones, bucketRecords, bucketKeys, bucketContacts, bucketPending} {
			if err := tx.Bucket(name).Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadAll reads every persisted zone, key set and contact into fresh
// in-memory Store, KeyRegistry and ContactRegistry instances.
func (db *DB) LoadAll() (*Store, *KeyRegistry, *ContactRegistry, error) {
	store := NewStore()
	keys := NewKeyRegistry()
	contacts := NewContactRegistry()

	origins, err := db.ListZones()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading zones: %w", err)
	}
	for _, origin := range origins {
		records, err := db.zoneRecords(origin)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("loading records for %s: %w", origin, err)
		}
		z := store.GetOrCreate(origin)
		for _, rr := range records {
			z.Insert(rr)
		}

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
		}

		switch addrs, ok, err := db.LoadContact(origin); {
		case err != nil:
			return nil, nil, nil, fmt.Errorf("loading contact for %s: %w", origin, err)
		case ok:
			contacts.Set(origin, addrs)
		}
	}
	return store, keys, contacts, nil
}

// ListZones returns every onboarded zone's origin.
func (db *DB) ListZones() ([]string, error) {
	var origins []string
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketZones)
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, _ []byte) error {
			origins = append(origins, string(k))
			return nil
		})
	})
	return origins, err
}

// LoadKey returns zone's KSK, if any.
func (db *DB) LoadKey(zone string) (*dns.DNSKEY, bool, error) {
	zk, ok, err := db.LoadZoneKeys(zone)
	if err != nil || !ok {
		return nil, false, err
	}
	return zk.KSK.DNSKEY, true, nil
}

// LoadZoneKeys returns zone's KSK and registered ZSKs.
func (db *DB) LoadZoneKeys(zone string) (*ZoneKeys, bool, error) {
	var sk storedKeys
	found := false
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketKeys)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(normalizeZone(zone)))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &sk)
	})
	if err != nil || !found || sk.KSK.DNSKEY == "" {
		return nil, false, err
	}
	zk := &ZoneKeys{KSK: &ManagedKey{DNSKEY: dnskeyFromText(sk.KSK.DNSKEY), Role: RoleKSK, CanAuthenticateTx: true}}
	for _, k := range sk.ZSKs {
		zk.ZSKs = append(zk.ZSKs, &ManagedKey{DNSKEY: dnskeyFromText(k.DNSKEY), Role: RoleZSK, CanAuthenticateTx: k.CanAuthenticateTx})
	}
	return zk, true, nil
}

// LoadContact returns the registered §11.4 contact addresses for zone, if
// any.
func (db *DB) LoadContact(zone string) ([]string, bool, error) {
	var sc storedContact
	found := false
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketContacts)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(normalizeZone(zone)))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &sc)
	})
	if err != nil || !found {
		return nil, false, err
	}
	return sc.Addresses, true, nil
}

// RecordTransaction appends entry to the §11.5 audit trail. It is written
// separately from CommitUpdate, after the update succeeded or failed, and
// a failure to write it never fails the update (see handler.go).
func (db *DB) RecordTransaction(entry AuditEntry) error {
	v, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return db.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAudit).Put(auditKey(entry.Zone, entry.At, entry.ID), v)
	})
}

func auditKey(zone string, at time.Time, id string) []byte {
	k := make([]byte, 0, len(zone)+1+8+len(id))
	k = append(k, normalizeZone(zone)...)
	k = append(k, 0)
	k = binary.BigEndian.AppendUint64(k, uint64(at.UnixNano()))
	return append(k, id...)
}

// RecentTransactions returns up to limit audit-trail entries for zone,
// newest first.
func (db *DB) RecentTransactions(zone string, limit int) ([]AuditEntry, error) {
	prefix := append([]byte(normalizeZone(zone)), 0)
	var entries []AuditEntry
	err := db.view(func(tx *bolt.Tx) error {
		b := bucket(tx, bucketAudit)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		// Position after the zone's last entry, then walk backwards.
		after := append(append([]byte(nil), prefix...), bytes.Repeat([]byte{0xff}, 9)...)
		k, v := c.Seek(after)
		if k == nil {
			k, v = c.Last()
		} else {
			k, v = c.Prev()
		}
		for ; k != nil && bytes.HasPrefix(k, prefix) && len(entries) < limit; k, v = c.Prev() {
			var e AuditEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			entries = append(entries, e)
		}
		return nil
	})
	return entries, err
}

// encodeRecords packs rrs in wire format, each preceded by its length.
func encodeRecords(rrs []dns.RR) ([]byte, error) {
	var out []byte
	for _, rr := range rrs {
		buf := make([]byte, dns.Len(rr)+len(rr.Header().Name)+16)
		n, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			return nil, fmt.Errorf("packing %s: %w", rr.Header().Name, err)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, buf[:n]...)
	}
	return out, nil
}

func decodeRecords(b []byte) ([]dns.RR, error) {
	var out []dns.RR
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("truncated record")
		}
		n := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if len(b) < n {
			return nil, errors.New("truncated record")
		}
		rr, _, err := dns.UnpackRR(b[:n], 0)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
		b = b[n:]
	}
	return out, nil
}

func dnskeyFromText(s string) *dns.DNSKEY {
	rr, err := dns.NewRR(s)
	if err != nil {
		return nil
	}
	k, _ := rr.(*dns.DNSKEY)
	return k
}

func putJSON(b *bolt.Bucket, key []byte, v any) error {
	enc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(key, enc)
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
