package sazu

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// This file computes the minimal edit to an existing NSEC/NSEC3 chain a
// partial (differential) push needs, so push-update no longer has to
// invalidate the whole chain the way ZoneData.PurgeNSEC does by default
// (see its own doc comment) -- see SAZU-PLAN.md for the design this
// implements.
//
// SAZU's split-signing model means only the customer's own signer can
// produce this edit: it's the only party holding the private key, so
// this computation necessarily lives on the client side (sazuctl calls
// it directly), even though the code itself is here rather than in
// cmd/sazuctl -- the underlying chain math (hashing, canonical/hash
// ordering, closest-encloser search) already lives in this package for
// the server's own NegativeProof, and duplicating it client-side to
// avoid one more exported name would risk the two copies drifting
// apart, exactly the kind of bug this package's own validation tooling
// (see plugin/sazu/verification) exists to catch.
//
// ChainState is what a client persists locally between pushes (see
// cmd/sazuctl's on-disk chain cache) -- its last-confirmed view of the
// server's actual chain. ComputeChainPatch never contacts the server: it
// reconstructs today's complete (name, type) membership purely from
// ChainState's own cached bitmaps, applies the requested ops, and runs
// the result back through the same BuildNSECChain/BuildNSEC3Chain a full
// push already uses -- then diffs the fresh, complete chain against
// ChainState to find the smallest true edit. This is deliberately not a
// hand-rolled split/merge implementation: reusing the already-correct,
// already-tested full-chain builder means two names inserted into the
// same gap in one push, or an insert and a removal in the same push,
// are handled correctly by construction, with no separate case to get
// right for each combination.

// ChainState is a client's local record of a zone's current NSEC/NSEC3
// chain, as last confirmed with the server.
type ChainState struct {
	// Scheme is "nsec" or "nsec3".
	Scheme string
	// Param is the zone's NSEC3PARAM; nil when Scheme is "nsec".
	Param *dns.NSEC3PARAM
	// Apex is the zone's origin.
	Apex string
	// Minttl is the zone's SOA minimum, used as every chain record's TTL
	// (RFC 4034 §4 / RFC 5155 §3).
	Minttl uint32
	// Records maps each real, lowercased FQDN currently in the zone to
	// its current chain record (a *dns.NSEC or *dns.NSEC3). For "nsec3",
	// that record's own Hdr.Name is the hashed owner name RFC 5155
	// actually uses on the wire -- Records itself is always keyed by the
	// real name, since that's what a client's own bookkeeping (which
	// names it has pushed content for) naturally works in terms of.
	Records map[string]dns.RR
}

// ChainOp is one content-level change relevant to chain maintenance:
// adding or removing RR type Type at Name. Multiple ops at the same name
// in one ComputeChainPatch call are fine -- e.g. two different types
// added to a brand-new name in the same push.
type ChainOp struct {
	Name string
	Type uint16
	Add  bool
}

// ChainPatch is ComputeChainPatch's result.
type ChainPatch struct {
	// Adds are new or patched chain records -- pass to SignZoneContent
	// (only the client holds the private key) and then Msg.Insert.
	Adds []dns.RR
	// Deletes are chain records for names removed entirely -- pass
	// directly to Msg.RemoveRRset (RFC 2136 §2.5.2 needs only their
	// Name/Rrtype, which is all these carry any meaningful value for).
	Deletes []dns.RR
	// Prerequisites are RFC 2136 §2.4.2 "RRset exists (value-dependent)"
	// assertions, one per touched record's prior value -- pass directly
	// to Msg.Used. The server rejects the whole update outright (see
	// EvaluatePrerequisites/statusErrStaleChain) if any has since
	// changed, rather than silently applying a patch computed against a
	// chain state that's since drifted.
	Prerequisites []dns.RR
	// NewRecords is the complete post-patch membership, keyed by real
	// name exactly like ChainState.Records -- once a push carrying this
	// patch is confirmed applied, a caller can just assign this directly
	// as its ChainState's new Records rather than re-deriving it from
	// Adds/Deletes (whose own Header().Name is the hashed owner name for
	// "nsec3", not the real name ChainState indexes by).
	NewRecords map[string]dns.RR
}

// contentTypesOf returns rec's type bitmap with every chain-mechanism
// type (NSEC, NSEC3, NSEC3PARAM, RRSIG) stripped out, leaving just the
// real content types a name actually holds -- what ComputeChainPatch's
// membership reconstruction needs, and the reverse of what
// BuildNSECChain/BuildNSEC3Chain add back in when building a fresh
// bitmap.
func contentTypesOf(rec dns.RR) map[uint16]bool {
	var bitmap []uint16
	switch v := rec.(type) {
	case *dns.NSEC:
		bitmap = v.TypeBitMap
	case *dns.NSEC3:
		bitmap = v.TypeBitMap
	}
	out := make(map[uint16]bool, len(bitmap))
	for _, t := range bitmap {
		switch t {
		case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeRRSIG:
			continue
		}
		out[t] = true
	}
	return out
}

// ComputeChainPatch computes the minimal edit to state's cached chain
// implied by ops. See this file's top-of-file comment for the overall
// approach. Returns an error if state is missing required fields, or an
// op would remove the last content type SAZU's own zone apex needs
// (SOA) -- the apex always exists once a zone is onboarded, so removing
// its last type isn't a chain-maintenance case, it's a malformed op.
func ComputeChainPatch(state *ChainState, ops []ChainOp) (*ChainPatch, error) {
	if state.Apex == "" {
		return nil, fmt.Errorf("chain state has no apex set")
	}
	if state.Scheme != "nsec" && state.Scheme != "nsec3" {
		return nil, fmt.Errorf("chain state has unknown scheme %q", state.Scheme)
	}
	if state.Scheme == "nsec3" && state.Param == nil {
		return nil, fmt.Errorf("nsec3 chain state has no NSEC3PARAM")
	}
	apex := strings.ToLower(dns.Fqdn(state.Apex))

	membership := make(map[string]map[uint16]bool, len(state.Records))
	for name, rec := range state.Records {
		membership[strings.ToLower(dns.Fqdn(name))] = contentTypesOf(rec)
	}
	if membership[apex] == nil {
		membership[apex] = map[uint16]bool{}
	}
	for _, op := range ops {
		name := strings.ToLower(dns.Fqdn(op.Name))
		if membership[name] == nil {
			membership[name] = map[uint16]bool{}
		}
		if op.Add {
			membership[name][op.Type] = true
			continue
		}
		delete(membership[name], op.Type)
		if len(membership[name]) == 0 {
			if name == apex {
				return nil, fmt.Errorf("cannot remove the zone apex's last content type")
			}
			delete(membership, name)
		}
	}

	synth := make([]dns.RR, 0, len(membership)+1)
	synth = append(synth, &dns.SOA{Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: state.Minttl}, Minttl: state.Minttl})
	for name, types := range membership {
		for t := range types {
			synth = append(synth, &dns.RFC3597{Hdr: dns.RR_Header{Name: name, Rrtype: t}})
		}
	}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: state.Minttl}, Minttl: state.Minttl}

	freshByName := make(map[string]dns.RR, len(membership))
	switch state.Scheme {
	case "nsec3":
		chain := BuildNSEC3Chain(soa, synth, NSEC3Options{Iterations: state.Param.Iterations, Salt: state.Param.Salt, OptOut: state.Param.Flags&1 != 0})
		byHash := make(map[string]dns.RR, len(chain))
		for _, rr := range chain {
			if n, ok := rr.(*dns.NSEC3); ok {
				byHash[strings.ToLower(n.Hdr.Name)] = n
			}
		}
		for name := range membership {
			owner := NSEC3Hash(name, state.Param) + "." + apex
			if rr, ok := byHash[owner]; ok {
				freshByName[name] = rr
			}
		}
	case "nsec":
		chain := BuildNSECChain(soa, synth)
		for _, rr := range chain {
			if n, ok := rr.(*dns.NSEC); ok {
				freshByName[strings.ToLower(n.Hdr.Name)] = n
			}
		}
	}

	patch := &ChainPatch{NewRecords: freshByName}
	touched := make(map[string]bool, len(membership))
	for name, fresh := range freshByName {
		old, existed := state.Records[name]
		if existed && rrEqualContent(old, fresh) {
			continue // unchanged -- nothing to assert, nothing to send
		}
		if existed {
			patch.Prerequisites = append(patch.Prerequisites, old)
			touched[name] = true
		}
		patch.Adds = append(patch.Adds, fresh)
	}
	for name, old := range state.Records {
		if _, stillThere := freshByName[name]; stillThere {
			continue
		}
		if !touched[name] {
			patch.Prerequisites = append(patch.Prerequisites, old)
		}
		patch.Deletes = append(patch.Deletes, old)
	}
	return patch, nil
}
