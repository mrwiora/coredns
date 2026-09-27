package sazu

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

// log follows the same convention as every other CoreDNS plugin (see
// e.g. plugin/hosts): log.Info/Warning/Error are always visible; log.Debug
// only prints once the Corefile also loads the `debug` plugin. There was
// no logging anywhere in this plugin before -- added specifically because
// a real production hang (a first-contact push that got no response at
// all, even after a minute) turned out to be undiagnosable without it:
// nothing here distinguished "stuck in the chain-of-trust network walk"
// from "silently dropped" from the outside.
var log = clog.NewWithPlugin("sazu")

// Sazu is the CoreDNS plugin implementing SAZU (Self-Authenticated Zone
// Update): a customer's own signer pushes DNSSEC-signed zone content,
// authenticated purely by SIG(0) (RFC 2931) riding on an RFC 2136 dynamic
// UPDATE, with no separate account/API-key handshake (§10.1/§10.2), over
// UDP, TCP, or HTTPS (§7.3). See the protocol specification (readme.md in github.com/mrwiora/sazu) for the full design;
// see plugin/sazu/docs/SAZU-PLAN.md for exactly what of it this port implements today.
type Sazu struct {
	Next plugin.Handler

	Zones       []string
	Store       *Store
	Keys        *KeyRegistry
	Contacts    *ContactRegistry
	Validator   ChainValidator
	Capture     *RawCapture
	RateLimiter *RateLimiter

	// IPRateLimiter enforces a global, per-source-IP flood/scan throttle
	// (§12's ERR_RATE_LIMITED), independent of RateLimiter's per-zone
	// daily quota: it bounds total UPDATE attempt volume from one address
	// regardless of which zone name(s) it targets, closing the gap a
	// per-zone-only quota leaves open against an attacker probing many
	// different candidate zone names from one address. Checked before
	// anything else in serveUpdate -- before SIG(0) verification, even --
	// since it exists to bound raw attempt volume, not just successfully
	// authenticated ones.
	IPRateLimiter *IPRateLimiter

	// Versions holds every zone's control-state version -- the counter
	// control changes must name as a prerequisite (see version.go).
	Versions *VersionRegistry

	// Pending holds DS-only KSK rollovers waiting out RolloverHoldDown
	// (see rollover.go).
	Pending *PendingRollovers

	// RolloverHoldDown is how long a KSK rollover not co-signed by the
	// old KSK waits before it can complete. setup.go defaults it to
	// DefaultRolloverHoldDown; zero applies such rollovers immediately.
	RolloverHoldDown time.Duration

	// now returns the current time; nil means time.Now. Tests override
	// it to step past a hold-down.
	now func() time.Time

	// SkipVersionCheck turns off the version-prerequisite requirement.
	// Only this package's own tests set it, for the many tests about
	// something else that build control messages by hand; the zero
	// value, and everything setup.go builds, enforces it.
	SkipVersionCheck bool

	// MaxSIG0Lifetime caps a SIG(0) record's validity window
	// (expiration - inception). Zero means DefaultMaxSIG0Lifetime.
	MaxSIG0Lifetime time.Duration

	// DB, if non-nil, persists every accepted UPDATE (see db.go): a
	// restart replays it back into Store/Keys instead of starting empty.
	// Nil is a fully supported mode -- purely in-memory, matching every
	// behavior this plugin had before persistence existed (what all of
	// this package's unit tests still use).
	DB *DB

	// InsecureSkipChainValidation disables the §10.2 chain-of-trust
	// cross-check at first contact. It exists purely for local testing,
	// where there is no real parent zone to publish a DS record against
	// -- see the onboarding guide. Never set true in production: with it
	// set, any self-signed key claiming any zone name is accepted on
	// first contact, which is exactly the spoofable behavior the
	// cross-check exists to prevent.
	InsecureSkipChainValidation bool

	// updateLocks serializes the whole authenticate-evaluate-apply
	// sequence for UPDATE requests -- but only against other requests
	// for the *same* zone, not every zone this instance serves. See
	// zoneLockStripes' own doc comment for why this is a fixed-size
	// array of stripes rather than one lock per zone name, or (the
	// original design) one lock for every zone at once: with a single
	// global lock, an expensive first-contact/rollover chain-of-trust
	// walk for one zone -- a real outbound network round trip that can
	// take a real amount of time -- blocked every *other* zone's
	// ordinary, already-authenticated pushes for its entire duration,
	// even though the two share no state that actually needs it.
	updateLocks [zoneLockStripes]sync.Mutex
}

// zoneLockStripes is how many lock stripes updateLockFor spreads zone
// names across. Fixed-size and allocated once as part of the Sazu
// struct itself (see updateLocks), rather than a map that would grow by
// one entry per distinct zone name ever presented -- exactly the kind
// of attacker-controllable unbounded growth the per-source-IP and
// per-zone rate limiters already have to guard against (see
// ipratelimit.go's own doc comment on why that matters), avoided here
// by construction instead of a sweep. 64 stripes make two different
// zones collide onto the same lock only 1-in-64 of the time at random
// -- more than enough to eliminate the original design's actual
// problem (one global lock, 1-in-1 collision, always) for the request
// volumes this plugin serves, without the complexity of an exact
// per-zone lock that would need its own lifecycle management.
const zoneLockStripes = 64

// updateLockFor returns the lock stripe for zone -- the same stripe
// every time for the same (case- and FQDN-normalized) zone name, so
// concurrent updates to that zone still serialize correctly against
// each other, while updates to a different zone very likely land on a
// different stripe and proceed independently.
func (s *Sazu) updateLockFor(zone string) *sync.Mutex {
	h := fnv.New32a()
	h.Write([]byte(normalizeZone(zone)))
	return &s.updateLocks[h.Sum32()%zoneLockStripes]
}

func (s *Sazu) Name() string { return "sazu" }

// ServeDNS implements plugin.Handler.
// ServeDNS implements plugin.Handler. s.Zones (from the Corefile) sets
// this instance's *static scope* -- e.g. "." to accept any domain at
// all, or a narrower umbrella zone to only accept subdomains delegated
// under one zone -- and is deliberately kept separate from which zones
// have actually been onboarded (dynamic, in s.Store): that separation is
// what lets a new customer domain be onboarded by sending it a signed
// push, with no Corefile edit or server restart needed per domain.
func (s *Sazu) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// Claim this UPDATE's captured bytes first, whatever happens to the
	// request next: an entry left behind by a request refused early (out
	// of scope, malformed, rate-limited) would otherwise sit in the
	// bounded capture table until evicted, crowding out legitimate ones.
	var raw []byte
	var haveRaw bool
	if r.Opcode == dns.OpcodeUpdate {
		raw, haveRaw = s.Capture.Take(w.RemoteAddr(), r.Id)
	}

	if len(r.Question) != 1 {
		return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
	}
	qname := r.Question[0].Name

	if r.Opcode == dns.OpcodeUpdate {
		// RFC 2136: the "question" of an UPDATE message is the zone
		// section, naming the zone directly -- no suffix matching, and
		// it may well be a zone never seen before (first contact).
		if plugin.Zones(s.Zones).Matches(qname) == "" {
			return s.nextOrRefuse(ctx, w, r, qname, "outside this instance's configured zone scope")
		}
		return s.serveUpdate(ctx, w, r, qname, raw, haveRaw)
	}

	if m, ok := s.versionAnswer(r); ok {
		return writeMsg(w, m)
	}

	// Ordinary query: find which *onboarded* zone (if any) qname falls
	// under -- a lookup against live state, not the static Corefile
	// list, since many customer zones can share one broad "sazu ." scope.
	// A qname within s.Zones' scope but never actually onboarded falls
	// through to Next rather than NXDOMAIN, so a broad scope like "."
	// doesn't swallow every other zone/plugin on the same server.
	_, z, ok := s.Store.FindZoneForName(qname)
	if !ok {
		return s.nextOrRefuse(ctx, w, r, qname, "not an onboarded zone")
	}
	return s.serveQuery(w, r, z)
}

// nextOrRefuse falls through to Next exactly like plugin.NextOrFailure,
// except when Next is nil: rather than that generic helper's SERVFAIL
// (its "no next plugin found" is a signal aimed at a misconfigured
// Corefile missing a catch-all, easily misread as sazu itself being
// broken or missing), it returns REFUSED directly -- the same
// convention plugin/auto already uses for exactly this situation ("If
// no next plugin is configured, it's more correct to return REFUSED as
// auto acts as an authoritative server"), which applies to sazu just as
// directly: declining a name that isn't one of its onboarded zones is
// an ordinary, everyday answer an authoritative server gives, not the
// kind of thing SERVFAIL exists to signal. reason is logged at debug
// level so an operator has a clear trail for *why* sazu declined a
// given query, in sazu's own logs, before whatever the final rcode
// becomes downstream.
func (s *Sazu) nextOrRefuse(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, qname, reason string) (int, error) {
	if s.Next == nil {
		log.Debugf("query %s: %s, refusing (no next plugin configured to try instead)", qname, reason)
		return dns.RcodeRefused, nil
	}
	return plugin.NextOrFailure(s.Name(), s.Next, ctx, w, r)
}

func (s *Sazu) serveQuery(w dns.ResponseWriter, r *dns.Msg, z *ZoneData) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	q := r.Question[0]
	rrs := z.Lookup(q.Name, q.Qtype)
	nameExists := z.NameExists(q.Name)
	log.Debugf("query %s/%s (zone %s, DO=%v): %d matching RRset(s), nameExists=%v",
		q.Name, dns.TypeToString[q.Qtype], z.Origin, isDNSSECRequested(r), len(rrs), nameExists)
	if len(rrs) == 0 && !nameExists {
		m.Rcode = dns.RcodeNameError
	} else {
		m.Answer = rrs // NOERROR/NODATA when the name exists but this type doesn't
		if len(rrs) > 0 && isDNSSECRequested(r) {
			// A validating resolver needs the covering RRSIG(s) in the
			// *same* answer as the RRset they cover, not as a separate
			// query -- without this, the zone would carry real
			// signatures (once actually pushed signed) that never
			// reached anyone asking for them, still producing exactly
			// the "RRSIGs Missing" bogus state this whole feature exists
			// to avoid.
			m.Answer = append(m.Answer, z.LookupRRSIG(q.Name, q.Qtype)...)
		}
	}

	if len(rrs) == 0 {
		// RFC 2308 §3: every negative response (NXDOMAIN here, or NODATA
		// in the "name exists but not this type" branch above) MUST
		// carry the zone's SOA in the authority section, so a resolver
		// knows how long it may cache the negative result for. Omitting
		// it doesn't make the *answer* wrong, but it silently defeats
		// negative caching -- every repeat query for the same
		// nonexistent name or type would otherwise bypass cache and hit
		// this server directly every time.
		if soa := z.SOA(); soa != nil {
			m.Ns = append(m.Ns, soa)
			if isDNSSECRequested(r) {
				m.Ns = append(m.Ns, z.LookupRRSIG(z.Origin, dns.TypeSOA)...)
				// RFC 4035 §3.1.3: the authenticated denial-of-existence
				// proof itself, without which a validating resolver has
				// to treat this negative answer as Bogus rather than
				// Insecure or Secure once a DS is published for this
				// zone. See ZoneData.NegativeProof and nsec.go's
				// top-of-file comment for why this can be empty (no NSEC
				// chain currently exists) even on a zone that has one on
				// other names, and why that's a safe degradation rather
				// than a bug.
				m.Ns = append(m.Ns, z.NegativeProof(q.Name, nameExists)...)
			}
		}
	}
	log.Debugf("query %s/%s: replying rcode=%s answer=%v authority=%v",
		q.Name, dns.TypeToString[q.Qtype], dns.RcodeToString[m.Rcode], m.Answer, m.Ns)
	return writeMsg(w, m)
}

// isDNSSECRequested reports whether r carries the EDNS0 DO bit -- the
// signal a validating resolver (or any DNSSEC-aware client) sets to ask
// for RRSIGs alongside ordinary answers.
func isDNSSECRequested(r *dns.Msg) bool {
	opt := r.IsEdns0()
	return opt != nil && opt.Do()
}

func (s *Sazu) serveUpdate(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, zone string, raw []byte, ok bool) (int, error) {
	txID := newTransactionID()
	remoteAddr := w.RemoteAddr().String()
	// authKeyTag/authKeyRole identify the key whose SIG(0) signature
	// authenticated this transaction, for attribution in the audit trail
	// below -- set once, right after that verification actually succeeds,
	// never before: a candidate key found in the wire message but not yet
	// verified is not proof of anything, and attributing an audit entry to
	// it would let an attacker frame an arbitrary key tag in the log
	// merely by naming it, with no need to ever prove possession of it.
	// statusDetail, when set, adds a human-readable second string to the
	// diagnostic TXT record (currently only a pending rollover's earliest
	// completion time).
	var statusDetail string
	var authKeyTag *uint16
	var authKeyRole string
	// reply is the sole exit point for this function: every response,
	// accepted or refused, goes through it, so the §12 audit trail (when
	// s.DB is configured) sees every transaction this server decided on,
	// not just the successful ones -- an operator investigating "why did
	// my push fail" needs the rejected attempts at least as much as the
	// accepted ones. A logging failure here is deliberately never the
	// reason an UPDATE itself fails: it's just logged, since the audit
	// trail is a record of what happened, not a gate on whether it can.
	reply := func(rcode int, status string) (int, error) {
		// Deliberately skip the audit-trail write for the two rejections
		// that exist specifically to bound a flood/scan: statusErrRateLimited
		// and statusErrTransportNotAllowed. IPRateLimiter bounds attempts
		// *per* address, not the number of distinct addresses -- a
		// first-contact attempt from a fresh (possibly spoofed) address
		// always gets one free pass through it, so an attacker who varies
		// the address on every packet can still generate one of these
		// rejections per packet, unboundedly. Persisting one DB row per
		// such attempt would turn the audit trail itself into exactly the
		// kind of resource-growth vector this whole defense exists to
		// avoid, for entries with little forensic value anyway (the
		// address is exactly the thing already suspected of being
		// unreliable). Every other rejection reason is still fully
		// audited, including ones IPRateLimiter itself did let through.
		if s.DB != nil && status != statusErrRateLimited && status != statusErrTransportNotAllowed {
			entry := AuditEntry{ID: txID, Zone: zone, RemoteAddr: remoteAddr, Rcode: dns.RcodeToString[rcode], Status: status, At: time.Now(), KeyTag: authKeyTag, KeyRole: authKeyRole}
			if err := s.DB.RecordTransaction(entry); err != nil {
				log.Errorf("update for %s: recording audit entry %s: %v", zone, txID, err)
			}
		}
		return replyWithStatusDetail(w, r, rcode, status, statusDetail)
	}

	log.Debugf("update for %s from %s: transaction %s, %d prerequisite(s), %d op(s)", zone, remoteAddr, txID, len(r.Answer), len(r.Ns))

	if s.IPRateLimiter != nil && !s.IPRateLimiter.Allow(remoteAddr) {
		// Checked before anything else -- SIG(0) verification included --
		// deliberately: this bounds raw attempt volume from remoteAddr
		// regardless of whether the attempt is even well-formed, which is
		// exactly what a flood/scan guard needs. See IPRateLimiter's own
		// doc comment for the gap this closes that RateLimiter's per-zone
		// quota (checked later, and only after SIG(0) verifies) cannot:
		// an attacker varying the target zone name gets a fresh quota
		// bucket every time, but never a fresh IPRateLimiter bucket.
		log.Warningf("update for %s from %s: rejected, source IP exceeded its update rate limit", zone, remoteAddr)
		return reply(dns.RcodeRefused, statusErrRateLimited)
	}

	if !ok {
		// §7.3 HTTPS/JSON carrier: UDP/TCP get here via
		// UDPDecorateReaderFunc/TCPDecorateReaderFunc into s.Capture, but
		// HTTPS/HTTP3 never go through a dns.Server's DecorateReader at
		// all -- core/dnsserver's ServerHTTPS/ServerHTTPS3 instead stash
		// the exact wire bytes doh.RequestToMsgWireWithAccept already
		// extracted (already decoded out of a JSON wire envelope, if the
		// client used one) directly on the request context, precisely so
		// a plugin like this one -- whose SIG(0)/RFC 2931 authentication
		// must verify against literal wire bytes, never a re-encoding --
		// has something to check over that transport too.
		if httpRaw, isHTTP := ctx.Value(dnsserver.RawRequestKey{}).([]byte); isHTTP {
			raw, ok = httpRaw, true
		}
	}
	if !ok {
		// No exact wire bytes captured for this request -- there is
		// nothing to verify a SIG(0) signature against. Fail closed
		// rather than trust a re-encoding of the parsed message.
		log.Warningf("update for %s from %s: no raw bytes captured for id %d, refusing", zone, w.RemoteAddr(), r.Id)
		return reply(dns.RcodeServerFailure, "")
	}

	// From here on, the only message this function looks at is the one
	// parsed from raw -- the exact bytes SIG(0) is verified against --
	// never the *dns.Msg the server handed in. The two are only
	// correlated by source address and 16-bit message ID, so a spoofed
	// packet with a matching ID could otherwise pair its own content
	// with someone else's genuinely signed bytes: the signature would
	// verify over the legitimate message while the forged one got
	// applied.
	signed := new(dns.Msg)
	if err := signed.Unpack(raw); err != nil ||
		signed.Id != r.Id || signed.Opcode != dns.OpcodeUpdate || signed.Response ||
		len(signed.Question) != 1 || !strings.EqualFold(signed.Question[0].Name, zone) ||
		signed.Question[0].Qtype != dns.TypeSOA || signed.Question[0].Qclass != dns.ClassINET {
		log.Warningf("update for %s from %s: captured bytes for id %d are not this request, refusing", zone, remoteAddr, r.Id)
		return reply(dns.RcodeFormatError, "")
	}
	r = signed

	lock := s.updateLockFor(zone)
	log.Debugf("update for %s: waiting for its zone's update lock stripe", zone)
	lock.Lock()
	defer lock.Unlock()
	log.Debugf("update for %s: acquired its zone's update lock stripe", zone)

	zk, alreadyPinned := s.Keys.Get(zone)
	var candidate *dns.DNSKEY
	var candidateRole KeyRole
	isRollover := false
	var sigErr error
	if alreadyPinned {
		// Ordinary push: try every key currently trusted to authenticate
		// a transaction for this zone -- the KSK, plus any registered
		// ZSK with CanAuthenticateTx (see keys.go's KeyRole doc comment
		// for what that split is for). A zone onboarded via publish-trust
		// always has at least the KSK and its paired ZSK here; a routine
		// publish-zone push only ever verifies against the ZSK, so this
		// loop's second iteration is the common case, not a fallback.
		for _, auth := range zk.Authenticators() {
			if err := VerifySIG0(raw, auth.DNSKEY); err == nil {
				candidate, candidateRole, sigErr = auth.DNSKEY, auth.Role, nil
				break
			} else {
				sigErr = err
			}
		}
		if candidate == nil {
			// §10.4 KSK rollover: none of today's authenticators signed
			// this transaction -- before giving up, check whether a
			// *different*, KSK-shaped (SEP-flagged) candidate DNSKEY
			// also present in these ops does. If so, this zone already
			// has a pinned key presenting a new one it can prove current
			// possession of; the caller still has to run the exact same
			// chain-of-trust recheck first contact requires (a matching
			// DS at the parent) before this actually takes effect.
			// Reusing first contact's whole trust model rather than also
			// requiring the *old* key's signature is deliberate: whoever
			// can get a DS published at the registrar already fully
			// controls the delegation regardless (the root of trust
			// first contact itself already rests on), so requiring only
			// that same proof here doesn't introduce a new attack
			// surface beyond what first contact already accepts.
			//
			// A candidate DNSKEY that is present but NOT SEP-flagged is
			// not a KSK rollover attempt at all -- see the separate,
			// much cheaper ZSK-registration path below, reached only
			// once a push has already authenticated successfully by
			// some other means (a ZSK is never itself trusted until an
			// already-trusted key vouches for it).
			if other, ferr := findCandidateKey(r.Ns, zone); ferr == nil && other.Flags&dns.SEP != 0 &&
				other.KeyTag() != zk.KSK.KeyTag() {
				log.Debugf("update for %s: rollover candidate key tag %d algorithm %d", zone, other.KeyTag(), other.Algorithm)
				if !algorithmMeetsFloor(other.Algorithm) {
					// Checked before spending any effort verifying its
					// signature or (further down) walking the chain of
					// trust -- same "cheap check first" reasoning as
					// first contact's own floor check below.
					log.Debugf("update for %s: rollover candidate key algorithm %d is below the minimum floor (RFC 8624 §3.1), refusing", zone, other.Algorithm)
					return reply(dns.RcodeRefused, statusErrWeakAlgorithm)
				}
				if verr := VerifySIG0(raw, other); verr == nil {
					candidate, candidateRole, isRollover, sigErr = other, RoleKSK, true, nil
				}
			}
		}
	} else {
		var ferr error
		candidate, ferr = findCandidateKey(r.Ns, zone)
		if ferr != nil {
			log.Debugf("update for %s: no candidate DNSKEY found in a first-contact push: %v", zone, ferr)
			return reply(dns.RcodeRefused, "")
		}
		log.Debugf("update for %s: first-contact candidate key tag %d algorithm %d", zone, candidate.KeyTag(), candidate.Algorithm)
		if !algorithmMeetsFloor(candidate.Algorithm) {
			log.Debugf("update for %s: candidate key algorithm %d is below the minimum floor (RFC 8624 §3.1), refusing", zone, candidate.Algorithm)
			return reply(dns.RcodeRefused, statusErrWeakAlgorithm)
		}
		if candidate.Flags&dns.SEP == 0 {
			// First contact establishes a zone's KSK -- the one and
			// only key ever anchored to a parent DS. A candidate
			// presented without the SEP (KSK) flag can never become
			// that; it can only ever be an optional ZSK, which by
			// definition doesn't exist until a KSK already does (see
			// keys.go's KeyRole doc comment). Refusing this cheaply,
			// before spending a SIG(0) verification or any chain-of-
			// trust effort on it, also gives a much clearer diagnostic
			// than the generic NOTAUTH a failed VerifySIG0 would produce
			// for what is actually a configuration mistake, not a
			// forged or malicious push.
			log.Debugf("update for %s: first-contact candidate key tag %d is not SEP-flagged (not a KSK), refusing", zone, candidate.KeyTag())
			return reply(dns.RcodeRefused, statusErrFirstContactNeedsKSK)
		}
		sigErr = VerifySIG0(raw, candidate)
		candidateRole = RoleKSK
	}
	if sigErr != nil {
		log.Debugf("update for %s: SIG(0) verification failed: %v", zone, sigErr)
		return reply(dns.RcodeNotAuth, "")
	}
	log.Debugf("update for %s: SIG(0) verified (rollover=%v)", zone, isRollover)
	// Recorded only now that verification has actually succeeded -- see
	// authKeyTag's own doc comment above for why.
	keyTag := candidate.KeyTag()
	authKeyTag = &keyTag
	authKeyRole = candidateRole.String()

	// A SIG(0) window longer than the server's maximum would keep a
	// captured message cryptographically valid for longer than needed.
	// (Replay itself is prevented by the SOA serial and version rules
	// below; this only bounds the window those have to hold across.)
	sig0 := isSig0(r)
	if sig0 == nil {
		// Can't happen once VerifySIG0 succeeded against the raw bytes,
		// but never index a nil record on the strength of that alone.
		return reply(dns.RcodeFormatError, "")
	}
	if !strings.EqualFold(sig0.SignerName, dns.Fqdn(zone)) {
		// The SIG(0) key is always one of the zone's own DNSKEYs, so its
		// signer name is the zone apex; anything else names some other
		// principal this server knows nothing about.
		log.Debugf("update for %s: SIG(0) signer name %s is not the zone apex, refusing", zone, sig0.SignerName)
		return reply(dns.RcodeNotAuth, "")
	}
	if lifetime := time.Duration(sig0.Expiration-sig0.Inception) * time.Second; lifetime > s.maxSIG0Lifetime() {
		log.Debugf("update for %s: SIG(0) validity window %s exceeds the %s maximum, refusing", zone, lifetime, s.maxSIG0Lifetime())
		return reply(dns.RcodeNotAuth, statusErrSIG0LifetimeTooLong)
	}

	prereqs, claimedVersion, versionPresent, err := splitVersionPrereq(r.Answer, zone)
	if err != nil {
		log.Debugf("update for %s: %v", zone, err)
		return reply(dns.RcodeFormatError, "")
	}

	// §10.6 registration record: a contact address (if this push carries
	// one) rides the same authenticated UPDATE as everything else, at a
	// reserved owner name -- see contact.go. Stripped out here, before
	// anything below treats r.Ns as zone content: it needs SIG(0)'s
	// authentication (already checked above) but none of DNSSEC's, since
	// it is never served.
	zoneOps, contactUpdate, err := splitContactOps(r.Ns, zone)
	if err != nil {
		log.Debugf("update for %s: invalid contact directive: %v", zone, err)
		return reply(dns.RcodeFormatError, "")
	}

	// A decommission directive (decommission.go) removes a zone entirely
	// -- KSK, every ZSK, all content and its chain, and the contact
	// registration -- rather than changing any of them, so none of the
	// ordinary content/key-management handling below applies to it.
	// Stripped out and handled here, on its own, before any of that runs.
	zoneOps, decommission, err := splitDecommissionOps(zoneOps, zone)
	if err != nil {
		log.Debugf("update for %s: invalid decommission directive: %v", zone, err)
		return reply(dns.RcodeFormatError, "")
	}
	zoneOps, cancelRollover, err := splitCancelRolloverOps(zoneOps, zone)
	if err != nil || (cancelRollover && (isRollover || !alreadyPinned)) {
		log.Debugf("update for %s: invalid cancel-rollover directive: %v", zone, err)
		return reply(dns.RcodeFormatError, "")
	}
	if touchesReservedName(zoneOps, zone) {
		log.Debugf("update for %s: update touches the reserved version name, refusing", zone)
		return reply(dns.RcodeFormatError, "")
	}

	// Replay protection for control changes (see version.go): anything
	// that changes the zone's control state -- onboarding, a rollover,
	// its DNSKEY RRset, its contact, decommission -- must name the
	// zone's current version, and increments it once applied. So must a
	// zone's first content push, which has no SOA serial yet to be
	// ordered by. A version that is present must match even where it
	// isn't required.
	touchesKeys := touchesDNSKEY(zoneOps, zone)
	isControl := !alreadyPinned || isRollover || decommission || touchesKeys || contactUpdate != nil || cancelRollover
	currentVersion := s.Versions.Get(zone)
	if !s.SkipVersionCheck {
		needsVersion := isControl
		if !needsVersion && containsAPEXSOA(zoneOps, zone) {
			existing, ok := s.Store.Get(zone)
			needsVersion = !ok || existing.SOA() == nil
		}
		switch {
		case needsVersion && !versionPresent:
			log.Debugf("update for %s: control change without a version prerequisite, refusing", zone)
			return reply(dns.RcodeRefused, statusErrVersionRequired)
		case versionPresent && claimedVersion != currentVersion:
			log.Debugf("update for %s: version prerequisite %d, zone is at %d, refusing", zone, claimedVersion, currentVersion)
			return reply(dns.RcodeNXRrset, statusErrStaleVersion)
		}
	}
	var newVersion *uint64
	if isControl {
		v := currentVersion + 1
		newVersion = &v
	}

	if decommission {
		if !alreadyPinned || isRollover || candidateRole != RoleKSK {
			log.Debugf("update for %s: decommission attempted by other than the zone's own pinned KSK, refusing", zone)
			return reply(dns.RcodeRefused, statusErrDecommissionRequiresKSK)
		}
		if s.DB != nil {
			if err := s.DB.DeleteZoneWithVersion(zone, *newVersion); err != nil {
				log.Errorf("update for %s: DB.DeleteZone failed: %v", zone, err)
				return reply(dns.RcodeServerFailure, "")
			}
		}
		s.Versions.Set(zone, *newVersion)
		s.Pending.Clear(zone)
		s.Store.DeleteZone(zone)
		s.Keys.DeleteZone(zone)
		s.Contacts.Set(zone, nil)
		log.Infof("update for %s: decommissioned (authenticated by KSK key tag %d)", zone, candidate.KeyTag())
		return reply(dns.RcodeSuccess, "")
	}

	// isFullPush: a real content push always carries the apex SOA
	// (sazuctl publish-zone) -- used for §12 quota metering, below, to
	// bucket it separately from a pure key-management push
	// (publish-trust's first contact, a KSK rollover, or a ZSK
	// add/retire), which changes no served content at all and costs this
	// server far less to process.
	isFullPush := containsAPEXSOA(zoneOps, zone)

	// Every update must be one of the message kinds (or an allowed
	// combination of them). One that changes nothing at all matches none.
	if len(zoneOps) == 0 && !isControl {
		log.Debugf("update for %s: carries no operation of any message kind, refusing", zone)
		return reply(dns.RcodeFormatError, "")
	}
	// A content push replaces the whole zone, so it has nothing to delete
	// -- except DNSKEYs, when it's combined with a key update.
	if isFullPush && hasNonDNSKEYDeletes(zoneOps) {
		log.Debugf("update for %s: content push carries delete operations, refusing", zone)
		return reply(dns.RcodeFormatError, "")
	}

	// Only the KSK may change the zone's key set or its contact: a ZSK
	// is the warm key an automation host holds for routine content
	// pushes, and letting it also register further ZSKs, retire the
	// legitimate ones, or redirect where sazu-watchd's alerts go would
	// turn a stolen ZSK into lasting control of the zone. (A rollover's
	// new KSK and first contact's KSK are KSKs by construction.)
	if candidateRole != RoleKSK && (touchesKeys || contactUpdate != nil || cancelRollover) {
		log.Debugf("update for %s: key or contact change authenticated by %s key tag %d, refusing", zone, candidateRole, candidate.KeyTag())
		return reply(dns.RcodeRefused, statusErrRequiresKSK)
	}

	// Every change to served content is a complete replacement of the
	// zone (the apex SOA marks one). A partial change would leave the
	// zone's NSEC/NSEC3 chain describing content that no longer exists,
	// and nothing here could produce a correct one in its place -- the
	// server never signs -- so negative answers would stop validating
	// until the next full push. Refused outright instead.
	if !isFullPush && changesChainRelevantContent(zoneOps) {
		log.Debugf("update for %s: partial content change without an apex SOA, refusing", zone)
		return reply(dns.RcodeRefused, statusErrFullZoneRequired)
	}

	if s.RateLimiter != nil {
		// §12 quota: a content push and a key-management push are
		// metered separately, since they cost very different amounts of
		// server effort. Checked here, before the expensive first-contact
		// chain-of-trust walk below, so an
		// already-exhausted quota doesn't also pay for that network round
		// trip.
		if !s.RateLimiter.Allow(zone, isFullPush) {
			log.Debugf("update for %s: rejected, quota exceeded (full=%v)", zone, isFullPush)
			return reply(dns.RcodeRefused, statusErrQuotaExceeded)
		}
	}

	if !alreadyPinned || isRollover {
		// A first-contact or rollover attempt is the one operation in
		// this package expensive enough to be worth protecting against a
		// spoofed-source-address flood specifically: it triggers a real
		// outbound network walk (VerifyChainOfTrust, below). IPRateLimiter
		// already bounds attempt volume per apparent source address, but
		// that protection is only meaningful over a transport where an
		// attacker can't just forge a fresh source address on every
		// packet with zero proof of controlling it -- true of plain UDP,
		// not of TCP or HTTPS/HTTP3 (both TLS-over-TCP and QUIC require
		// their own handshake-based address validation before any real
		// work happens). Without this, an attacker could spoof a
		// different source address on every UDP packet, each one still
		// getting IPRateLimiter's full per-address budget and each still
		// costing this server a real outbound query to the DNS root/TLD
		// infrastructure -- turning a rate limiter meant to bound that
		// exact cost into no protection at all.
		if !connectionOriented(ctx, w) {
			log.Debugf("update for %s: refusing a %s attempt over a connectionless transport (spoofable source address) from %s",
				zone, candidateKindLabel(isRollover), remoteAddr)
			return reply(dns.RcodeRefused, statusErrTransportNotAllowed)
		}
		if !s.InsecureSkipChainValidation {
			log.Infof("update for %s: %s, starting chain-of-trust walk to the DNS root (this makes real outbound DNS queries and can take a while on a restricted network)", zone, candidateKindLabel(isRollover))
			start := time.Now()
			err := s.Validator.VerifyChainOfTrust(zone, candidate)
			log.Infof("update for %s: chain-of-trust walk finished in %s, err=%v", zone, time.Since(start), err)
			if err != nil {
				status := ""
				if ce, ok := err.(*ChainError); ok {
					switch ce.Op {
					case "no-ds-published":
						// §12's status-code convention: the specific, by far
						// most common first-contact failure -- "you haven't
						// told your registrar about this key yet" -- gets its
						// own diagnostic so a client can say exactly that,
						// rather than a bare REFUSED indistinguishable from a
						// wrong key or a broken chain elsewhere.
						status = statusErrNoDSPublished
					case "weak-ds-digest":
						// The key does match a published DS, but only a
						// SHA-1 one -- the §10.7 digest floor.
						status = statusErrWeakDSDigest
					case "key-mismatch":
						// A DS *is* published for this zone, just not for
						// this key. Distinct from ERR_NO_DS_PUBLISHED and
						// deliberately not phrased as "wrong key" or
						// "attack": the DS found here may well be
						// legitimate DNSSEC this zone's current host
						// already publishes under its own key, unrelated
						// to SAZU entirely -- exactly the case a client
						// needs flagged rather than silently lumped in
						// with a bare REFUSED.
						status = statusErrUnknownSigner
					}
				}
				return reply(dns.RcodeRefused, status)
			}
		}
	}

	// KSK rollover hold-down (see rollover.go): the old KSK's
	// co-signature over the new DNSKEY RRset lets a rollover apply now;
	// without it, the rollover must wait out s.RolloverHoldDown from its
	// first attempt, which records it as pending so the zone's contact
	// can be alerted and the current KSK holder can cancel it.
	if isRollover {
		var coSigned bool
		zoneOps, coSigned = stripKSKCoSignature(zoneOps, zone, zk.KSK.DNSKEY)
		if !coSigned && s.RolloverHoldDown > 0 {
			now := s.timeNow()
			pending, ok := s.Pending.Get(zone)
			if !ok || !sameKey(pending.KSK, candidate) {
				pending = PendingRollover{KSK: candidate, RequestedAt: now}
				if s.DB != nil {
					if err := s.DB.SetPendingRollover(zone, pending); err != nil {
						log.Errorf("update for %s: %v", zone, err)
						return reply(dns.RcodeServerFailure, "")
					}
				}
				s.Pending.Set(zone, pending)
				log.Warningf("update for %s: KSK rollover to key tag %d not co-signed by the current KSK; pending until %s",
					zone, candidate.KeyTag(), pending.RequestedAt.Add(s.RolloverHoldDown).UTC().Format(time.RFC3339))
			}
			if notBefore := pending.RequestedAt.Add(s.RolloverHoldDown); now.Before(notBefore) {
				statusDetail = "not before " + notBefore.UTC().Format(time.RFC3339)
				return reply(dns.RcodeRefused, statusErrRolloverPending)
			}
			log.Infof("update for %s: pending KSK rollover to key tag %d completed its hold-down", zone, candidate.KeyTag())
		}
	}

	// Any push that isn't a KSK rollover may also carry a ZSK change:
	// registering a new one, or retiring one already registered -- see
	// keys.go's KeyRole doc comment for what that split is for. This
	// covers both an ordinary already-pinned push (the cheap add/retire
	// path) and first contact itself: sazuctl publish-trust always
	// generates and presents a KSK and a ZSK together, so first contact
	// is exactly where that ZSK is meant to get registered, in the same
	// transaction that pins the KSK. Not checked for a rollover: the
	// rollover path already fully establishes this transaction's key
	// state on its own, and a customer can always change the ZSK set in
	// a follow-up push once a rollover has succeeded.
	var newZSK *dns.DNSKEY
	var retiredZSKTag uint16
	var hasRetiredZSK bool
	if !isRollover {
		var zerr error
		newZSK, zerr = findNewZSKCandidate(r.Ns, zone, zk)
		if zerr != nil {
			log.Debugf("update for %s: %v", zone, zerr)
			return reply(dns.RcodeFormatError, "")
		}
		if newZSK != nil {
			log.Debugf("update for %s: new ZSK candidate key tag %d algorithm %d", zone, newZSK.KeyTag(), newZSK.Algorithm)
			if !algorithmMeetsFloor(newZSK.Algorithm) {
				log.Debugf("update for %s: new ZSK candidate algorithm %d is below the minimum floor (RFC 8624 §3.1), refusing", zone, newZSK.Algorithm)
				return reply(dns.RcodeRefused, statusErrWeakAlgorithm)
			}
		}
		retiredZSKTag, hasRetiredZSK = findRetiredZSKKeytag(r.Ns, zone, zk)
	}

	// The KSK the zone will be pinned to once this update applies --
	// the only key allowed to sign its DNSKEY RRset (see
	// VerifySignedRRsetsSplit).
	kskAfter := candidate
	if alreadyPinned && !isRollover {
		kskAfter = zk.KSK.DNSKEY
	}

	// Any update that touches the DNSKEY RRset must carry that RRset
	// complete, exactly as it will be served afterwards, and it must be
	// exactly the pinned KSK plus the registered ZSKs this update leaves
	// behind. The first half is what makes signature verification
	// (which checks the records the update carries) a check on what
	// will actually be served; the second keeps the served key set and
	// the key registry from ever drifting apart -- e.g. a rollover that
	// also slips in an unregistered key, or one update adding one ZSK
	// while silently dropping another.
	if touchesKeys || !alreadyPinned || isRollover {
		var current []dns.RR
		if existing, ok := s.Store.Get(zone); ok {
			current = existing.Lookup(dns.Fqdn(zone), dns.TypeDNSKEY)
		}
		expected := []*dns.DNSKEY{kskAfter}
		if alreadyPinned {
			for _, zsk := range zk.ZSKs {
				if hasRetiredZSK && zsk.KeyTag() == retiredZSKTag {
					continue
				}
				expected = append(expected, zsk.DNSKEY)
			}
		}
		if newZSK != nil {
			expected = append(expected, newZSK)
		}
		resulting := resultingDNSKEYSet(current, zoneOps, zone)
		if !sameKeySet(resulting, expected) || !sameKeySet(addedDNSKEYs(zoneOps, zone), resulting) {
			log.Debugf("update for %s: DNSKEY RRset after this update (%d key(s)) does not match the pinned KSK plus registered ZSKs (%d key(s)), or is not carried complete",
				zone, len(resulting), len(expected))
			return reply(dns.RcodeRefused, statusErrDNSKEYSetMismatch)
		}
	}

	z := s.Store.GetOrCreate(zone)
	if rcode, status, err := EvaluatePrerequisites(z, prereqs, dns.ClassINET); err != nil {
		log.Debugf("update for %s: prerequisite failed: %v", zone, err)
		return reply(rcode, status)
	}

	// Replay protection for content: a full push's SOA serial must move
	// forward (RFC 1982 arithmetic), the same rule secondaries and
	// resolvers already rely on -- so an older complete zone can never
	// be re-installed over a newer one.
	if isFullPush {
		if current := z.SOA(); current != nil {
			if pushed := apexSOA(zoneOps, zone); pushed != nil && !serialGreater(pushed.Serial, current.Serial) {
				log.Debugf("update for %s: SOA serial %d is not greater than the current %d, refusing", zone, pushed.Serial, current.Serial)
				return reply(dns.RcodeRefused, statusErrStaleSerial)
			}
		}
	}

	// §4's full content verification: confirm the content being pushed
	// is itself validly DNSSEC-signed, not just that the transaction
	// carrying it was. Mandatory, unconditionally -- SIG(0) alone proves
	// who sent the push, never that the zone content it carries would
	// actually validate for a real DNSSEC resolver once served, which is
	// the one property this whole plugin exists to guarantee.
	//
	// The candidate set is every key currently trusted to sign content:
	// for first contact, just the brand-new KSK (nothing else exists
	// yet); for a KSK rollover, the new KSK plus any ZSKs that already
	// existed under the old one (a rollover never invalidates them --
	// see KeyRegistry.PinKSK); otherwise, zone's unchanged existing
	// content-signer set. A newly registered ZSK in *this* push is
	// deliberately not added to its own candidate set -- see
	// findNewZSKCandidate's caller comment above for why that
	// combination isn't supported.
	contentCandidates := []*dns.DNSKEY{candidate}
	if isRollover {
		for _, zsk := range zk.ZSKs {
			contentCandidates = append(contentCandidates, zsk.DNSKEY)
		}
	} else if alreadyPinned {
		contentCandidates = zk.ContentSigners()
	}
	if status, err := VerifySignedRRsetsSplit(contentCandidates, []*dns.DNSKEY{kskAfter}, zoneOps, dns.ClassINET, time.Now()); err != nil {
		log.Debugf("update for %s: content signature verification failed: %v", zone, err)
		if status == "" {
			status = statusErrSigInvalid
		}
		// Name the failing RRset, so the client can say exactly what to
		// fix (the protocol's §6.2).
		statusDetail = strings.TrimPrefix(err.Error(), "sazu: ")
		return reply(dns.RcodeNotAuth, status)
	}

	// Persist before mutating memory: if the disk write fails, memory
	// stays exactly as it was before this request, rather than the two
	// disagreeing about whether the update actually happened. Built
	// additively, not as an exclusive choice: first contact
	// (sazuctl publish-trust) pins the KSK *and* registers the ZSK it
	// always presents alongside it, in the same transaction.
	var keyChange *KeyChange
	if !alreadyPinned || isRollover {
		keyChange = &KeyChange{PinKSK: candidate}
	}
	switch {
	case newZSK != nil:
		// CanAuthenticateTx is fixed true for a ZSK registered this way:
		// the DNSKEY wire format has no field to signal otherwise (only
		// the ZONE and SEP bits are defined; every other bit is reserved
		// must-be-zero per RFC 4034 §2.1.1), so there is no channel for
		// a push to ask for false here. See ManagedKey's doc comment --
		// the field still exists for a future, out-of-band way to
		// register one (an admin API, say) that isn't limited to what
		// the wire format itself can express.
		if keyChange == nil {
			keyChange = &KeyChange{}
		}
		keyChange.AddZSK = &ManagedKey{DNSKEY: newZSK, Role: RoleZSK, CanAuthenticateTx: true}
	case hasRetiredZSK:
		if keyChange == nil {
			keyChange = &KeyChange{}
		}
		tag := retiredZSKTag
		keyChange.RetireZSK = &tag
	}
	if s.DB != nil {
		if err := s.DB.CommitUpdateWithVersion(zone, newVersion, keyChange, zoneOps, dns.ClassINET, contactUpdate); err != nil {
			log.Errorf("update for %s: DB.CommitUpdate failed: %v", zone, err)
			return reply(dns.RcodeServerFailure, "")
		}
		log.Debugf("update for %s: committed to DB", zone)
	}

	// A full push (containsAPEXSOA -- always the zone's complete content)
	// replaces everything served except the apex DNSKEY RRset, all under
	// one lock acquisition (ZoneData.PurgeContentAndApply), so a
	// concurrent query never observes a record transiently missing that
	// both existed before this push and exists after it. Anything else
	// that got this far only changes the DNSKEY RRset (partial content
	// changes were refused above), which the NSEC/NSEC3 chain doesn't
	// describe, so it is applied as-is.
	var applyErr error
	if isFullPush {
		applyErr = z.PurgeContentAndApply(zoneOps, dns.ClassINET)
	} else {
		applyErr = ApplyUpdateOps(z, zoneOps, dns.ClassINET)
	}
	if applyErr != nil {
		log.Errorf("update for %s: applying update ops failed: %v", zone, applyErr)
		return reply(dns.RcodeFormatError, "")
	}

	switch {
	case !alreadyPinned:
		s.Keys.PinKSK(zone, candidate)
		log.Infof("update for %s: onboarded and pinned to KSK key tag %d", zone, candidate.KeyTag())
	case isRollover:
		s.Keys.PinKSK(zone, candidate)
		log.Infof("update for %s: KSK rolled over, now pinned to key tag %d (was %d)", zone, candidate.KeyTag(), zk.KSK.KeyTag())
	}
	switch {
	case newZSK != nil:
		if err := s.Keys.AddZSK(zone, newZSK, true); err != nil {
			// Shouldn't happen -- findNewZSKCandidate already excluded
			// any key tag already registered -- but AddZSK is the single
			// source of truth for that invariant, so defer to it rather
			// than duplicate its check here.
			log.Errorf("update for %s: %v", zone, err)
			return reply(dns.RcodeServerFailure, "")
		}
		log.Infof("update for %s: registered new ZSK key tag %d", zone, newZSK.KeyTag())
	case hasRetiredZSK:
		s.Keys.RetireZSK(zone, retiredZSKTag)
		log.Infof("update for %s: retired ZSK key tag %d", zone, retiredZSKTag)
	}
	if newVersion != nil {
		s.Versions.Set(zone, *newVersion)
		if _, pending := s.Pending.Get(zone); pending {
			s.Pending.Clear(zone)
			if !isRollover {
				log.Infof("update for %s: pending KSK rollover cancelled by a control change authenticated by the current KSK", zone)
			}
		}
	}
	if contactUpdate != nil && s.Contacts != nil {
		s.Contacts.Set(zone, contactUpdate.Addresses)
		log.Debugf("update for %s: contact registration updated (%d address(es))", zone, len(contactUpdate.Addresses))
	}
	log.Debugf("update for %s: accepted", zone)
	return reply(dns.RcodeSuccess, "")
}

// candidateKindLabel names what kind of candidate-key event this is, for
// log messages shared between first contact and rollover.
func candidateKindLabel(isRollover bool) string {
	if isRollover {
		return "key rollover"
	}
	return "first-contact"
}

// connectionOriented reports whether this UPDATE arrived over a
// transport that requires a completed handshake -- proof of actually
// controlling the claimed source address -- before either side can
// exchange any real data: TCP, or HTTPS/HTTP3 (both TLS-over-TCP and
// QUIC perform their own handshake-based address validation), as opposed
// to plain UDP, where a single forged packet can claim any source
// address at all with nothing to disprove it.
//
// HTTPS/HTTP3 is detected via dnsserver.RawRequestKey's presence on ctx
// -- set unconditionally by both ServeHTTP methods -- rather than by
// inspecting w.RemoteAddr()'s concrete net.Addr type: ServerHTTPS3
// happens to construct its DoHWriter's RemoteAddr as a *net.UDPAddr
// (QUIC itself runs over UDP), which would otherwise look
// indistinguishable from plain, spoofable UDP by address type alone,
// even though QUIC's own handshake makes it just as address-validated
// as TCP.
func connectionOriented(ctx context.Context, w dns.ResponseWriter) bool {
	if _, isHTTP := ctx.Value(dnsserver.RawRequestKey{}).([]byte); isHTTP {
		return true
	}
	addr := w.RemoteAddr()
	return addr != nil && addr.Network() == "tcp"
}

// findCandidateKey looks for the Add-shaped, SEP-flagged (KSK-shaped)
// DNSKEY at zone's apex among update ops -- the candidate key a
// first-contact or §10.4 KSK-rollover push introduces itself with. A
// first-contact push (sazuctl publish-trust) always establishes a KSK
// and a ZSK together, and a rollover re-asserts every registered ZSK
// alongside the new KSK; those non-SEP keys are never candidates here
// and never count toward "more than one candidate" -- only a second
// SEP-flagged key does. See findNewZSKCandidate for the ZSK side.
func findCandidateKey(updateOps []dns.RR, zone string) (*dns.DNSKEY, error) {
	zoneLower := strings.ToLower(dns.Fqdn(zone))
	var ksk, zsk *dns.DNSKEY
	for _, rr := range updateOps {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		h := key.Header()
		if h.Class != dns.ClassINET || h.Rdlength == 0 || !strings.EqualFold(h.Name, zoneLower) {
			continue // a delete-shaped DNSKEY op (§2.5.2/.3's Rdlength==0 form,
			// or §2.5.4's Class-NONE-with-full-rdata one -- a KSK rollover's
			// own explicit delete of the superseded key is exactly this
			// latter shape), or for a different name
		}
		if key.Flags&dns.SEP != 0 {
			if ksk != nil {
				return nil, fmt.Errorf("more than one candidate DNSKEY in update")
			}
			ksk = key
			continue
		}
		if zsk == nil {
			zsk = key
		}
	}
	if ksk != nil {
		return ksk, nil
	}
	if zsk != nil {
		// No SEP-flagged candidate at all -- the caller (first contact)
		// diagnoses this specifically (statusErrFirstContactNeedsKSK)
		// rather than the bare "no candidate" below.
		return zsk, nil
	}
	return nil, fmt.Errorf("no candidate DNSKEY found for %s", zone)
}

// findNewZSKCandidate looks for exactly one Add-shaped, ZSK-shaped (not
// SEP-flagged) DNSKEY at zone's apex among updateOps that isn't already
// registered in zk -- the shape both an ordinary, already-authenticated
// push (add-zsk, or rotate-key -role zsk) and a first-contact push
// (sazuctl publish-trust, which always presents a KSK and its paired
// ZSK together) use to register a new ZSK (see keys.go's KeyRole doc
// comment). zk may be nil (treated as "no zone keys yet," so nothing is
// ever already registered) -- which is exactly the first-contact case.
// Returns ok with a nil key, no error, when no such candidate is
// present, which is the overwhelmingly common case for a push that
// isn't about key management at all.
func findNewZSKCandidate(updateOps []dns.RR, zone string, zk *ZoneKeys) (*dns.DNSKEY, error) {
	zoneLower := strings.ToLower(dns.Fqdn(zone))
	var found *dns.DNSKEY
	for _, rr := range updateOps {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		h := key.Header()
		if h.Rdlength == 0 || h.Class != dns.ClassINET || !strings.EqualFold(h.Name, zoneLower) {
			continue // not an Add-shaped DNSKEY at the apex
		}
		if key.Flags&dns.SEP != 0 {
			continue // KSK-shaped -- the rollover path handles this, not this one
		}
		if zk != nil {
			if _, already := zk.FindZSK(key.KeyTag()); already {
				continue // already registered -- not a new candidate
			}
		}
		if found != nil {
			return nil, fmt.Errorf("more than one new ZSK candidate in update")
		}
		found = key
	}
	return found, nil
}

// findRetiredZSKKeytag looks for an RFC 2136 §2.5.4 "delete one RR"
// DNSKEY op (Class NONE, full rdata) at zone's apex among updateOps
// whose key tag matches a ZSK currently registered in zk, and returns
// that key tag. A "delete RRset" op (Class ANY, empty rdata) is
// deliberately not treated as a ZSK retirement here -- it
// would remove the *entire* DNSKEY RRset, the KSK included, which is
// never what retiring one specific ZSK means; RFC 2136's delete-one-RR
// form exists precisely so one record can be removed from a multi-
// record RRset without disturbing the others, which is what this needs.
func findRetiredZSKKeytag(updateOps []dns.RR, zone string, zk *ZoneKeys) (uint16, bool) {
	if zk == nil {
		return 0, false
	}
	zoneLower := strings.ToLower(dns.Fqdn(zone))
	for _, rr := range updateOps {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		h := key.Header()
		if h.Class != dns.ClassNONE || !strings.EqualFold(h.Name, zoneLower) {
			continue
		}
		if _, isZSK := zk.FindZSK(key.KeyTag()); isZSK {
			return key.KeyTag(), true
		}
	}
	return 0, false
}

// containsAPEXSOA reports whether updateOps adds a real SOA record at
// zone's apex.
func containsAPEXSOA(updateOps []dns.RR, zone string) bool {
	zoneLower := strings.ToLower(dns.Fqdn(zone))
	for _, rr := range updateOps {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		h := soa.Header()
		if h.Rdlength > 0 && strings.EqualFold(h.Name, zoneLower) {
			return true
		}
	}
	return false
}

// changesChainRelevantContent reports whether updateOps touches anything
// a NSEC/NSEC3 chain's bitmaps need to reflect -- i.e. anything other
// than an apex DNSKEY (a key rotation or ZSK add/retire, which never
// changes what's actually served), a chain record itself, or an RRSIG
// covering any of those (content-signature verification is mandatory on
// every push, so a key-management push always carries one covering its
// DNSKEY, which is exactly as chain-irrelevant as the DNSKEY it covers).
// serveUpdate refuses an update that isn't a full push (containsAPEXSOA)
// yet reports true here: it would change content the chain describes,
// with no replacement chain the server could trust or compute.
func changesChainRelevantContent(updateOps []dns.RR) bool {
	for _, rr := range updateOps {
		switch rr.Header().Rrtype {
		case dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
			continue
		case dns.TypeRRSIG:
			sig, ok := rr.(*dns.RRSIG)
			if ok && (sig.TypeCovered == dns.TypeDNSKEY || sig.TypeCovered == dns.TypeNSEC ||
				sig.TypeCovered == dns.TypeNSEC3 || sig.TypeCovered == dns.TypeNSEC3PARAM) {
				continue
			}
			return true
		default:
			return true
		}
	}
	return false
}

func (s *Sazu) timeNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Sazu) maxSIG0Lifetime() time.Duration {
	if s.MaxSIG0Lifetime > 0 {
		return s.MaxSIG0Lifetime
	}
	return DefaultMaxSIG0Lifetime
}

// touchesDNSKEY reports whether updateOps changes, or re-signs, zone's
// apex DNSKEY RRset in any way: an add or delete of a DNSKEY at the
// apex, a delete of the apex's whole RRset or name, or an RRSIG covering
// the DNSKEY RRset.
func touchesDNSKEY(updateOps []dns.RR, zone string) bool {
	for _, rr := range updateOps {
		h := rr.Header()
		if !strings.EqualFold(h.Name, dns.Fqdn(zone)) {
			continue
		}
		switch h.Rrtype {
		case dns.TypeDNSKEY:
			return true
		case dns.TypeANY:
			if h.Class == dns.ClassANY {
				return true // §2.5.3 delete all RRsets from the apex name
			}
		case dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeDNSKEY {
				return true
			}
		}
	}
	return false
}

// hasNonDNSKEYDeletes reports whether updateOps contains an RFC 2136
// delete (class ANY or NONE) of anything but a DNSKEY.
func hasNonDNSKEYDeletes(updateOps []dns.RR) bool {
	for _, rr := range updateOps {
		h := rr.Header()
		if (h.Class == dns.ClassANY || h.Class == dns.ClassNONE) && h.Rrtype != dns.TypeDNSKEY {
			return true
		}
	}
	return false
}

// addedDNSKEYs returns every Add-shaped DNSKEY at zone's apex among
// updateOps.
func addedDNSKEYs(updateOps []dns.RR, zone string) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range updateOps {
		key, ok := rr.(*dns.DNSKEY)
		if ok && key.Hdr.Class == dns.ClassINET && key.Hdr.Rdlength > 0 && strings.EqualFold(key.Hdr.Name, dns.Fqdn(zone)) {
			out = append(out, key)
		}
	}
	return out
}

// resultingDNSKEYSet applies updateOps' DNSKEY-relevant operations, in
// order and with RFC 2136 §2.5 semantics, to current (the apex DNSKEY
// RRset served today) and returns the set that would be served after the
// update. A full push's purge never touches the DNSKEY RRset, so this
// holds for every kind of update.
func resultingDNSKEYSet(current []dns.RR, updateOps []dns.RR, zone string) []*dns.DNSKEY {
	var set []*dns.DNSKEY
	for _, rr := range current {
		if key, ok := rr.(*dns.DNSKEY); ok {
			set = append(set, key)
		}
	}
	for _, rr := range updateOps {
		h := rr.Header()
		if !strings.EqualFold(h.Name, dns.Fqdn(zone)) {
			continue
		}
		switch {
		case h.Rrtype == dns.TypeDNSKEY && h.Class == dns.ClassINET && h.Rdlength > 0:
			key := rr.(*dns.DNSKEY)
			if !containsKey(set, key) {
				set = append(set, key)
			}
		case h.Rrtype == dns.TypeDNSKEY && h.Class == dns.ClassNONE:
			key := rr.(*dns.DNSKEY)
			kept := set[:0:0]
			for _, k := range set {
				if !sameKey(k, key) {
					kept = append(kept, k)
				}
			}
			set = kept
		case h.Class == dns.ClassANY && h.Rdlength == 0 && (h.Rrtype == dns.TypeDNSKEY || h.Rrtype == dns.TypeANY):
			set = nil
		}
	}
	return set
}

// sameKey reports whether a and b are the same DNSKEY, ignoring TTL and
// owner-name case.
func sameKey(a, b *dns.DNSKEY) bool {
	return a.Flags == b.Flags && a.Protocol == b.Protocol && a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey
}

func containsKey(set []*dns.DNSKEY, key *dns.DNSKEY) bool {
	for _, k := range set {
		if sameKey(k, key) {
			return true
		}
	}
	return false
}

// sameKeySet reports whether a and b hold the same keys, ignoring order
// and duplicates.
func sameKeySet(a, b []*dns.DNSKEY) bool {
	for _, k := range a {
		if !containsKey(b, k) {
			return false
		}
	}
	for _, k := range b {
		if !containsKey(a, k) {
			return false
		}
	}
	return true
}

func writeMsg(w dns.ResponseWriter, m *dns.Msg) (int, error) {
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// statusErrNoDSPublished is one of §12's SAZU status codes, carried as a
// diagnostic TXT record per that section: "On the raw-DNS carrier this
// rides as a short diagnostic TXT record in the response's Additional
// section." Every status code in §12's list is implemented at this
// point (see the other statusErr* constants below and in prereq.go/
// sign.go); see plugin/sazu/docs/SAZU-PLAN.md for the full accounting.
const statusErrNoDSPublished = "ERR_NO_DS_PUBLISHED"

// statusErrUnknownSigner is another of §12's status codes: a DS record is
// published for the target zone, but none of them match the candidate
// key. Unlike statusErrNoDSPublished, this does not mean "nothing is
// there yet" -- something else already has DNSSEC set up for this zone,
// which the operator needs to understand (it may simply be the zone's
// current host, e.g. mid-migration) before doing anything that might
// disturb it.
const statusErrUnknownSigner = "ERR_UNKNOWN_SIGNER"

// statusErrSigInvalid is another of §12's status codes: emitted when a
// pushed RRset's RRSIG doesn't actually verify against the
// candidate/pinned key -- content-signature verification is mandatory
// on every push.
const statusErrSigInvalid = "ERR_SIG_INVALID"

// statusErrWeakAlgorithm is another of §12's status codes: a first-contact
// candidate key's algorithm doesn't meet §10.7's minimum floor (RFC 8624
// §3.1) -- see algorithm.go.
const statusErrWeakAlgorithm = "ERR_WEAK_ALGORITHM"

// statusErrQuotaExceeded is another of §12's status codes: this zone has
// already used up its content-push or key-management-push quota for the
// current rolling 24h window -- see RateLimiter and containsAPEXSOA.
// §12 also names a distinct ERR_RATE_LIMITED code (see
// statusErrRateLimited) -- that one is a separate, faster-timescale,
// per-source-IP flood throttle, not just a synonym for this.
const statusErrQuotaExceeded = "ERR_QUOTA_EXCEEDED"

// statusErrRateLimited is §12's remaining status code: remoteAddr has
// exceeded IPRateLimiter's global, per-source-IP UPDATE rate over the
// current rolling 1-minute window -- distinct from statusErrQuotaExceeded
// (a per-*zone* daily churn quota, checked only after SIG(0) verifies)
// specifically because this one bounds raw attempt volume from an
// address regardless of which zone it targets or whether the attempt is
// even well-formed.
const statusErrRateLimited = "ERR_RATE_LIMITED"

// statusErrTransportNotAllowed: this first-contact or key-rollover
// attempt arrived over a connectionless transport (plain UDP) -- see
// connectionOriented. Not one of §12's named codes (the design doc
// predates the HTTPS/JSON carrier and this specific spoofing concern),
// but the same diagnostic-TXT convention as the rest of them.
const statusErrTransportNotAllowed = "ERR_TRANSPORT_NOT_ALLOWED"

// statusErrStaleSerial is another of §12's status codes: a push built
// with BuildFullZonePush's previousSOA staleness guard (RFC 2136 §2.4.2)
// was rejected because the zone's current SOA no longer matches what the
// push was built against -- see EvaluatePrerequisites.
const statusErrStaleSerial = "ERR_STALE_SERIAL"

// statusErrFirstContactNeedsKSK is not one of §12's original status
// codes (the design doc predates the optional KSK/ZSK split) but follows
// its same diagnostic-TXT convention: a first-contact candidate DNSKEY
// was presented without the SEP (KSK) flag set. See keys.go's KeyRole
// doc comment for why a ZSK can never be what establishes a zone's
// initial trust -- only a KSK can, so first contact refuses anything
// else with this specific diagnostic rather than a bare, uninformative
// REFUSED.
const statusErrFirstContactNeedsKSK = "ERR_FIRST_CONTACT_REQUIRES_KSK"

// statusErrExpiredSignature is another of §12's status codes: distinct
// from the more general statusErrSigInvalid -- emitted when a pushed
// RRset's RRSIG would otherwise verify against the candidate/pinned key
// (right name, type,
// key tag, and algorithm, and a cryptographically valid signature) but
// falls outside its own inception/expiration window. Telling this apart
// from "no valid signature at all" matters operationally: this one means
// "re-sign and re-push," not "something is wrong with the key or the
// content."
const statusErrExpiredSignature = "ERR_EXPIRED_SIGNATURE"

// statusErrDecommissionRequiresKSK is not one of §12's original status
// codes (decommissioning a zone didn't exist when the design doc was
// written) but follows its same diagnostic-TXT convention: a
// decommission directive (decommission.go) was authenticated by
// something other than the zone's own currently-pinned KSK -- an
// already-registered ZSK, or a rollover-shaped candidate. Removing a
// zone entirely is at least as consequential as establishing or rolling
// over its KSK, so it requires exactly the same authenticator those do,
// never the lighter-weight ZSK routine content pushes use.
const statusErrDecommissionRequiresKSK = "ERR_DECOMMISSION_REQUIRES_KSK"

// statusErrRequiresKSK: an update that changes the zone's DNSKEY RRset
// or its registered contact was authenticated by a ZSK. Only the pinned
// KSK may do either -- see the check in serveUpdate.
const statusErrRequiresKSK = "ERR_KEY_MANAGEMENT_REQUIRES_KSK"

// statusErrFullZoneRequired: an update changed served content without
// carrying the zone's apex SOA, i.e. it wasn't a complete replacement of
// the zone -- the only kind of content change SAZU accepts.
const statusErrFullZoneRequired = "ERR_FULL_ZONE_REQUIRED"

// statusErrDNSKEYSetMismatch: an update touching the DNSKEY RRset
// didn't carry that RRset complete, or the RRset it would leave served
// isn't exactly the pinned KSK plus the registered ZSKs.
const statusErrDNSKEYSetMismatch = "ERR_DNSKEY_RRSET_MISMATCH"

// statusErrVersionRequired: a control change (or a zone's first content
// push) carried no version prerequisite -- see version.go.
const statusErrVersionRequired = "ERR_VERSION_REQUIRED"

// statusErrStaleVersion: the version prerequisite doesn't match the
// zone's current version -- a replay, or something else changed the
// zone's control state since the client read it. Re-read and re-sign.
const statusErrStaleVersion = "ERR_STALE_VERSION"

// statusErrSIG0LifetimeTooLong: the SIG(0) record's validity window is
// longer than the server accepts -- see DefaultMaxSIG0Lifetime.
const statusErrSIG0LifetimeTooLong = "ERR_SIG0_LIFETIME_TOO_LONG"

// statusErrRolloverPending: a KSK rollover not co-signed by the current
// KSK is waiting out its hold-down; the diagnostic TXT's second string
// says when it can complete. See rollover.go.
const statusErrRolloverPending = "ERR_ROLLOVER_PENDING"

// statusErrWeakDSDigest: the candidate KSK matches a DS at the parent,
// but only one with a SHA-1 digest (§7.2 accepts SHA-256/SHA-384 only).
const statusErrWeakDSDigest = "ERR_WEAK_DS_DIGEST"

// edeCodes maps each SAZU status code to the RFC 8914 Extended DNS Error
// INFO-CODE it is reported under. Anything the server refuses as a
// matter of policy is 18 (Prohibited); the few with a more specific
// registered code use it; the rest are 0 (Other Error). The SAZU code
// itself always travels as the EXTRA-TEXT.
var edeCodes = map[string]uint16{
	statusErrWeakAlgorithm:           dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm,
	statusErrWeakDSDigest:            dns.ExtendedErrorCodeUnsupportedDSDigestType,
	statusErrSigInvalid:              dns.ExtendedErrorCodeDNSBogus,
	statusErrExpiredSignature:        dns.ExtendedErrorCodeSignatureExpired,
	statusErrNoDSPublished:           dns.ExtendedErrorCodeProhibited,
	statusErrUnknownSigner:           dns.ExtendedErrorCodeProhibited,
	statusErrFirstContactNeedsKSK:    dns.ExtendedErrorCodeProhibited,
	statusErrDecommissionRequiresKSK: dns.ExtendedErrorCodeProhibited,
	statusErrRequiresKSK:             dns.ExtendedErrorCodeProhibited,
	statusErrTransportNotAllowed:     dns.ExtendedErrorCodeProhibited,
	statusErrQuotaExceeded:           dns.ExtendedErrorCodeProhibited,
	statusErrRateLimited:             dns.ExtendedErrorCodeProhibited,
	statusErrFullZoneRequired:        dns.ExtendedErrorCodeProhibited,
	statusErrDNSKEYSetMismatch:       dns.ExtendedErrorCodeProhibited,
	statusErrVersionRequired:         dns.ExtendedErrorCodeProhibited,
	statusErrRolloverPending:         dns.ExtendedErrorCodeProhibited,
}

// replyWithStatus replies to r with rcode and, if status is non-empty,
// reports it two ways: as an RFC 8914 Extended DNS Error (INFO-CODE from
// edeCodes, the status as EXTRA-TEXT) when the request carried EDNS(0) --
// RFC 6891 forbids an OPT record in a reply to a request without one --
// and, for clients without EDNS, as a diagnostic TXT record at the zone
// apex in the Additional section.
func replyWithStatus(w dns.ResponseWriter, r *dns.Msg, rcode int, status string) (int, error) {
	return replyWithStatusDetail(w, r, rcode, status, "")
}

// replyWithStatusDetail is replyWithStatus with an optional human-readable
// detail, sent as the diagnostic TXT record's second string.
func replyWithStatusDetail(w dns.ResponseWriter, r *dns.Msg, rcode int, status, detail string) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = rcode
	if status != "" {
		txt := []string{status}
		if detail != "" {
			txt = append(txt, detail)
		}
		m.Extra = append(m.Extra, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
			Txt: txt,
		})
		if r.IsEdns0() != nil {
			m.SetEdns0(dns.DefaultMsgSize, false)
			opt := m.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: edeCodes[status], ExtraText: status})
		}
	}
	return writeMsg(w, m)
}
