package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coredns/coredns/plugin/sazu"

	"github.com/miekg/dns"
)

// This file is push-update's local NSEC/NSEC3 chain cache: what lets a
// partial (differential) push patch the zone's existing denial-of-
// existence chain incrementally instead of forcing the server to
// discard it until the next full push (see ZoneData.PurgeNSEC and
// SAZU-PLAN.md for why a partial push couldn't do this before). SAZU's
// split-signing model means only the customer's own signer can compute
// and sign this patch -- the server never holds the private key -- so
// the client needs its own local memory of the chain to diff against;
// sazu.ComputeChainPatch (plugin/sazu/chainpatch.go) is the actual
// algorithm, this file is just its on-disk persistence.
//
// One file per zone, named after it, next to the running sazuctl binary
// (not the current working directory, and not next to -key -- literally
// beside the executable, since that's the one "local" location that
// doesn't depend on which key or directory a particular invocation
// happens to use).

// execDir returns the directory containing the currently-running
// sazuctl binary, resolving symlinks so e.g. a PATH shim doesn't change
// the answer. Falls back to "." if it can't be determined (a sandboxed
// or unusual environment) -- push-update still works without a cache,
// it just can't offer incremental chain maintenance.
func execDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// sanitizeZoneForFilename replaces every character a zone name can
// legally contain that isn't safe unescaped in a filename (a wildcard
// label's "*", or a literal "/" from a \DDD-escaped byte) with "_" --
// real SAZU zones are ordinary hostnames, so this rarely does anything,
// but a cache path must never let a zone name escape its directory.
func sanitizeZoneForFilename(zone string) string {
	zone = strings.TrimSuffix(dns.Fqdn(zone), ".")
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, zone)
}

// chainCachePath returns the path sazuctl reads/writes zone's chain
// cache from, next to the running binary.
func chainCachePath(zone string) string {
	return filepath.Join(execDir(), sanitizeZoneForFilename(zone)+".nsec-cache.json")
}

// chainCacheFile is the on-disk JSON shape -- a thin, directly
// serializable mirror of sazu.ChainState, storing each record in zone
// presentation format (round-tripped via dns.NewRR) rather than
// inventing a custom binary or field-by-field encoding for two record
// types with fairly different shapes.
type chainCacheFile struct {
	Zone    string            `json:"zone"`
	Scheme  string            `json:"scheme"`
	Apex    string            `json:"apex"`
	Minttl  uint32            `json:"minttl"`
	NSEC3   *chainCacheNSEC3  `json:"nsec3,omitempty"`
	Records map[string]string `json:"records"`
}

type chainCacheNSEC3 struct {
	Iterations uint16 `json:"iterations"`
	Salt       string `json:"salt"`
	OptOut     bool   `json:"opt_out"`
}

// loadChainCache reads zone's local chain cache, if one exists. ok is
// false (with a nil error) when no cache file is present at all -- the
// ordinary case for a zone push-update has never patched the chain for,
// or before this feature existed -- which callers should treat as "no
// chain maintenance available for this push," not an error.
func loadChainCache(zone string) (state *sazu.ChainState, ok bool, err error) {
	path := chainCachePath(zone)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading chain cache %s: %w", path, err)
	}
	var f chainCacheFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, false, fmt.Errorf("parsing chain cache %s: %w", path, err)
	}

	state = &sazu.ChainState{Scheme: f.Scheme, Apex: f.Apex, Minttl: f.Minttl, Records: make(map[string]dns.RR, len(f.Records))}
	if f.NSEC3 != nil {
		state.Param = &dns.NSEC3PARAM{Hash: dns.SHA1, Iterations: f.NSEC3.Iterations, Salt: f.NSEC3.Salt}
		if f.NSEC3.OptOut {
			state.Param.Flags = 1
		}
	}
	for name, text := range f.Records {
		rr, err := dns.NewRR(text)
		if err != nil {
			return nil, false, fmt.Errorf("chain cache %s: record for %s: %w", path, name, err)
		}
		state.Records[name] = rr
	}
	return state, true, nil
}

// saveChainCache writes zone's local chain cache, replacing any
// existing one -- called after every push (full or partial) that
// establishes or successfully patches a chain, so the next push-update
// has an up-to-date view to diff against.
func saveChainCache(zone string, state *sazu.ChainState) error {
	f := chainCacheFile{Zone: dns.Fqdn(zone), Scheme: state.Scheme, Apex: state.Apex, Minttl: state.Minttl, Records: make(map[string]string, len(state.Records))}
	if state.Param != nil {
		f.NSEC3 = &chainCacheNSEC3{Iterations: state.Param.Iterations, Salt: state.Param.Salt, OptOut: state.Param.Flags&1 != 0}
	}
	for name, rr := range state.Records {
		f.Records[name] = rr.String()
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	path := chainCachePath(zone)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing chain cache %s: %w", path, err)
	}
	return nil
}

// chainStateFromPush extracts the chain sazu.ChainState a just-built,
// just-signed full-zone push (push.Ns, from BuildFullZonePush(Split)(NSEC3))
// actually established, for saveChainCache to persist. names is every
// real name the push touches (the zone apex plus every rr in rrs) --
// needed to recover NSEC3's hash-owner records back to the real names
// sazu.ChainState indexes by (see ChainState's own doc comment for why).
func chainStateFromPush(zone string, soa *dns.SOA, rrs []dns.RR, push *dns.Msg) *sazu.ChainState {
	names := map[string]bool{strings.ToLower(dns.Fqdn(zone)): true}
	for _, rr := range rrs {
		names[strings.ToLower(dns.Fqdn(rr.Header().Name))] = true
	}

	var param *dns.NSEC3PARAM
	byOwner := make(map[string]dns.RR)
	for _, rr := range push.Ns {
		switch v := rr.(type) {
		case *dns.NSEC:
			byOwner[strings.ToLower(v.Hdr.Name)] = v
		case *dns.NSEC3:
			byOwner[strings.ToLower(v.Hdr.Name)] = v
		case *dns.NSEC3PARAM:
			param = v
		}
	}
	if len(byOwner) == 0 {
		return nil // this push carried no chain at all (shouldn't happen for push-zone, but nothing to cache)
	}

	state := &sazu.ChainState{Apex: dns.Fqdn(zone), Minttl: soa.Minttl, Records: make(map[string]dns.RR, len(names))}
	if param != nil {
		state.Scheme = "nsec3"
		state.Param = param
		for name := range names {
			owner := sazu.NSEC3Hash(name, param) + "." + strings.ToLower(dns.Fqdn(zone))
			if rr, ok := byOwner[owner]; ok {
				state.Records[name] = rr
			}
		}
	} else {
		state.Scheme = "nsec"
		for name := range names {
			if rr, ok := byOwner[name]; ok {
				state.Records[name] = rr
			}
		}
	}
	return state
}
