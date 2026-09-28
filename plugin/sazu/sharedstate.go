package sazu

import "sync"

// sharedState is what the plugin knows about its zones, loaded from one
// database. Every plugin instance configured with that database shares
// it, so the old and new instances that overlap during a Corefile reload
// see each other's updates and serialize on the same locks; otherwise an
// update accepted by the old instance would be missing from the new one's
// memory, zone version included.
type sharedState struct {
	db       *DB
	store    *Store
	keys     *KeyRegistry
	contacts *ContactRegistry
	versions *VersionRegistry
	pending  *PendingRollovers
	locks    *UpdateLocks
	refs     int
}

var (
	sharedMu sync.Mutex
	shared   = map[string]*sharedState{}
)

// acquireState returns the state for the database at path, loading it on
// first use. Each call must be paired with releaseState.
func acquireState(path string) (*sharedState, error) {
	db, err := Open(path)
	if err != nil {
		return nil, err
	}
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if st, ok := shared[db.Path()]; ok {
		st.refs++
		return st, nil
	}
	store, keys, contacts, err := db.LoadAll()
	if err != nil {
		return nil, err
	}
	versions, err := db.LoadVersions()
	if err != nil {
		return nil, err
	}
	pending, err := db.LoadPendingRollovers()
	if err != nil {
		return nil, err
	}
	st := &sharedState{db: db, store: store, keys: keys, contacts: contacts,
		versions: NewVersionRegistry(), pending: NewPendingRollovers(), locks: new(UpdateLocks), refs: 1}
	for zone, v := range versions {
		st.versions.Set(zone, v)
	}
	for zone, pr := range pending {
		st.pending.Set(zone, pr)
	}
	shared[db.Path()] = st
	return st, nil
}

// releaseState drops one reference to the state for the database at path.
func releaseState(path string) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if st, ok := shared[path]; ok {
		if st.refs--; st.refs <= 0 {
			delete(shared, path)
		}
	}
}
