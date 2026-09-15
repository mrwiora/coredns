# SAZU threat model

This document ties together the security reasoning already embedded,
decision by decision, throughout this codebase's own doc comments into one
consolidated picture: who the parties are, what each can and can't do, and
what a compromise of each looks like. It exists because that reasoning was
previously scattered across dozens of individual comments with no single
place to check the overall posture from — a gap identified in review, not
a description of a known-complete process.

Organized by STRIDE (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege). Every countermeasure
cited here already exists in the code; **identified gaps are called out
explicitly, inline, rather than left implicit.**

## 1. Actors

- **Customer**: owns a domain, holds its KSK and ZSK private keys. SAZU's
  server never holds, sees, or needs a customer's private key material at
  any point.
- **SAZU operator**: runs one or more CoreDNS instances with the `sazu`
  plugin, and optionally `sazu-watchd`. May or may not be the same party as
  the customer (a hosting provider running this for many customers is the
  primary intended shape).
- **Registrar**: holds the domain's actual parent-zone delegation and DS
  record. Entirely outside SAZU's control; SAZU only ever *reads* it.
- **The real DNS root and TLD infrastructure**: what `VerifyChainOfTrust`
  walks to confirm a DS record genuinely exists at the parent.
- **Validating and non-validating resolvers**: consumers of the zone's
  served content. A validating resolver checks RRSIGs; a non-validating one
  does not (relevant below, under Tampering).
- **An attacker**: on-path (network) or off-path (spoofing), with no
  legitimate credentials of their own, whose goal is one of the threats
  below.
- **(Once `SAZU-CLUSTER.md` is built) A partner instance**: another SAZU
  process holding the same cluster secret, in the same replication group.

## 2. Assets

- Customer zone content and its DNSSEC signatures (public once served, but
  integrity and availability both matter).
- The apex DNSKEY RRset (KSK + ZSKs) per zone — public key material only;
  SAZU's own database never contains a private key.
- The §10.6 contact registration (deliberately never served as public DNS
  content).
- The audit trail (`audit_log`).
- The cluster secret, once clustering exists.
- The SAZU host/process itself (out of SAZU's own scope to protect, but a
  trust boundary this model has to state explicitly — see §4).

## 3. Trust boundaries

- **Customer ↔ SAZU server**: RFC 2136 UPDATE over TCP/HTTPS, authenticated
  by SIG(0) (RFC 2931).
- **SAZU server ↔ registrar**: none, directly. The registrar's DS record is
  read via ordinary, unauthenticated-at-that-hop DNS queries as part of the
  chain-of-trust walk (§4's own DNSSEC validation is what makes that safe
  despite the hop itself being unauthenticated).
- **SAZU server ↔ DNS root/TLD**: ordinary DNS queries, validated end to end
  against a **hardcoded root trust anchor** (see the gap called out in §5.1).
- **SAZU server ↔ resolver**: ordinary DNS, authenticated by RRSIG for any
  resolver that chooses to validate.
- **SAZU server ↔ SAZU host filesystem**: `db PATH`'s SQLite file. Its
  confidentiality/integrity depends entirely on host-level access control,
  which is explicitly **outside SAZU's own scope** — see §5.2.
- **(Future) SAZU instance ↔ SAZU instance**: the cluster secret's
  AEAD-sealed gossip channel — see §5.6.

## 4. Spoofing (impersonating a legitimate party)

**Threat: an attacker who has never controlled a domain tries to onboard it
or push content for it anyway.**

- Countermeasure: every UPDATE is authenticated by SIG(0) — a signature
  over the transaction itself, verified against currently-registered keys
  (`VerifySIG0`). An attacker with no matching private key cannot produce
  a valid transaction at all, regardless of what content it claims to
  carry.
- Countermeasure: first contact additionally requires the candidate KSK to
  match a real DS record at the domain's actual parent zone —
  `VerifyChainOfTrust` performs a genuine DNSSEC-validated walk from the
  hardcoded root anchor down to the zone's parent (`chain.go`:
  `verifyAnyRRSIG` checks a real cryptographic signature at every hop, not
  merely "a DS record with this key tag happened to be returned"). Merely
  generating a keypair and self-signing a push is insufficient; the
  attacker would also need to control the domain's actual registrar-level
  delegation.
- Countermeasure: a first-contact or rollover candidate below RFC 8624's
  minimum algorithm floor is refused before any signature or network
  effort is spent on it (`algorithmMeetsFloor`), closing off weak-algorithm
  impersonation attempts cheaply.

**Threat: an attacker impersonates a registered *partner* instance (once
clustering exists).** See §5.6.

## 5. Tampering (modifying content or state)

**Threat: an attacker on the network path modifies a push in transit, or
crafts a push carrying content the sender didn't actually sign.**

- Countermeasure: mandatory content-signature verification
  (`VerifySignedRRsets`), unconditional on every push with no way to
  disable it. SIG(0) alone only proves *who sent the transaction*; RRSIG
  verification independently proves *the content itself* was validly
  signed by a currently-trusted key. Both are required, checked
  separately, for different reasons.
- Countermeasure: a DNSKEY RRset change (add-zsk/retire-zsk/KSK rollover)
  must be covered by an RRSIG over its *complete* resulting membership,
  never a signature computed over only the changed record (`push.go`'s
  `buildDNSKEYRRsetPush` family) — a fix made this session after finding
  the earlier behavior left a served RRset with no signature that actually
  covered it, which a real validating resolver would flag as bogus.

**Threat: an attacker with host-level access to the SAZU server's `db`
file tampers with stored content directly, bypassing the network path
entirely.**

- Partial mitigation, not a full one: a validating resolver would still
  reject tampered zone content, because the attacker cannot forge a new,
  valid RRSIG for it without the customer's private key (which the server
  never holds, so neither does anyone who compromises it). Tampered
  content served alongside its now-mismatched original RRSIG fails
  validation.
- **Gap**: this protection only helps against a *validating* resolver. A
  non-validating one accepts tampered content served this way without any
  indication anything is wrong. This is an inherent property of DNSSEC
  itself, not something specific to SAZU, but worth stating plainly: SAZU's
  security model assumes the resolver population that matters is
  validating; it provides no protection for content served to a
  non-validating one beyond what host-level access control already has to
  provide.
- **Gap, explicitly out of SAZU's scope**: host/filesystem access control
  to the `db` file and the running process itself is entirely the
  operator's responsibility. SAZU's own design already reflects this
  boundary correctly (it never stores a private key that host compromise
  could steal), but it's worth stating as an explicit assumption rather
  than leaving it implicit.

**Threat: a captured, still-valid push is replayed to revert a zone to an
earlier state.**

This is the one gap this review surfaced that wasn't previously flagged
anywhere in the codebase's own comments, and is worth walking through in
full:

- Every `sazuctl` command signs its SIG(0) transaction with a **fixed
  one-hour validity window** (`now.Add(-time.Minute), now.Add(time.Hour)`
  — identical across all eight call sites in `cmd/sazuctl/main.go`). A
  captured copy of any push's raw wire bytes remains a *literally valid,
  independently re-acceptable* transaction for that entire hour after it
  was first sent, regardless of what has happened on the server since.
- For an ordinary `publish-zone` re-push, replaying an *older* one is
  bounded by the `previousSerial` staleness guard — but only when the
  client actually sets it, and it is optional (explicitly "omit it (0) for
  a zone's first content push," with no enforcement that a *later* push
  must set it either). A customer's automation that omits it on every push
  is not protected: a captured older `publish-zone` transaction, replayed
  within its hour, reverts the zone to that earlier content with no
  staleness check to catch it.
- **The concrete, worse case is key management, which has no staleness
  guard at all**: `findNewZSKCandidate`'s "already registered" check
  (`zk.FindZSK`) only inspects the *current* registered-ZSK set. A ZSK that
  has since been retired is indistinguishable, from this check's
  perspective, from one that was never registered at all. A captured
  `add-zsk` transaction for a since-retired key, replayed within its
  one-hour window, silently re-registers exactly the key the customer
  explicitly removed — with no error, no warning, and (per this session's
  own RRSIG-completeness fix) a technically well-formed, currently-correct
  DNSKEY RRset signature covering it, since the replay is processed by the
  same code path a genuine new registration would use.
- **This is a real, currently unmitigated gap.** The natural fix mirrors
  what `previousSerial` already does for content: a monotonically
  increasing, mandatory nonce or sequence number covering key-management
  operations specifically (add-zsk, retire-zsk, a rollover, and now
  decommission), rejected if it doesn't strictly exceed whatever the
  server last saw for that zone. This has not been designed in detail or
  implemented; it's flagged here as the one concrete "spot we are missing"
  this review found.

## 6. Repudiation (denying an action, or being unable to prove one happened)

- Countermeasure: the audit trail (`audit_log`) records one row per
  transaction, accepted or rejected, including the specific key tag and
  role that authenticated it (`AuditEntry.KeyTag`/`KeyRole`, added this
  session) — for a zone with more than one registered ZSK, this is what
  actually answers "which signer pushed this," not just "some zone
  changed."
- Countermeasure: a decommissioned zone's audit history survives its
  removal (`DB.DeleteZone` deliberately never touches `audit_log`) — an
  operator can still answer "what happened to this zone" after it's gone.
- **Gap**: the audit trail is not itself tamper-evident. It has no hash
  chaining, no append-only enforcement at the database level, and no
  external attestation. An operator (or anyone else) with direct write
  access to the `db` file can alter or delete audit history with nothing
  to detect it. Reasonable given the audit trail's own stated purpose (an
  operational record, not a compliance-grade tamper-proof log), but worth
  stating as a boundary rather than leaving it assumed.

## 7. Information Disclosure

- Countermeasure: the §10.6 contact registration is deliberately never
  served as public DNS content, and is stripped out of a push before
  anything treats the rest of it as zone content (`splitContactOps`) —
  it exists specifically so a customer's alerting address isn't
  incidentally published to the world.
- Zone content itself carries no confidentiality expectation — it's public
  DNS data by definition, so this isn't a threat in the traditional sense.
- **(Future) Countermeasure**: the cluster secret's AEAD-sealed gossip
  payload (`SAZU-CLUSTER.md` §4) keeps which zones exist in a group, their
  digests, and pulled content confidential from a network observer between
  instances, once built.
- **Gap**: the `db` file itself, and the audit trail's remote-address/
  timestamp data within it, has no confidentiality protection beyond
  host-level file permissions — again an explicit operator-scope boundary,
  not something SAZU encrypts at rest.

## 8. Denial of Service

- Countermeasure: `IPRateLimiter` bounds raw UPDATE attempt volume per
  source address, checked *before* SIG(0) verification — so an attacker
  gains nothing from crafting well-formed-looking garbage, since volume
  alone is what's bounded here regardless of validity.
- Countermeasure: `RateLimiter`'s per-zone quota (full-content vs.
  key-management, tracked independently) bounds legitimate-looking churn
  once a push has actually authenticated, checked before the expensive
  first-contact chain-of-trust network walk so an already-exhausted quota
  never also pays for that round trip.
- Countermeasure: a first-contact or rollover attempt — the one operation
  expensive enough to be worth this — is refused outright over a
  connectionless transport (plain UDP), specifically because a spoofed
  source address could otherwise defeat `IPRateLimiter`'s whole premise by
  varying on every packet at zero cost.
- Countermeasure: both rate limiters sweep their own state periodically,
  bounding memory growth to "recently active keys," not "every distinct
  key or address ever seen" — otherwise an attacker varying source
  IPs/zone names could grow server memory unboundedly for free.
- **Gap, identified in prior review, restated here**: `RateLimiter`/
  `IPRateLimiter` are per-process, in-memory, with no cluster awareness.
  Once `SAZU-CLUSTER.md` is implemented, a party able to reach every
  instance in a group gets that group's *size* multiplied against every
  quota, since each instance counts independently with no shared state.
  Worth resolving before clustering ships further, not after.
- **Gap**: `audit_log` has no retention or pruning policy and grows
  unboundedly. Over a long enough timeframe for a busy zone, this is a
  slow, low-severity disk-exhaustion vector as much as an operational
  nuisance.
- **Gap, structural rather than a flaw**: the hardcoded root trust anchor
  (§5.1) fails *closed* when it goes stale (a chain-of-trust walk simply
  can never succeed again), which is the secure choice, but it manifests
  as a total, silent onboarding/rollover outage across every deployed
  instance simultaneously — an availability risk worth planning for
  operationally even though it's not an attacker-triggered one.

## 9. Elevation of Privilege

- Countermeasure: the KSK/ZSK role split (`keys.go`'s `KeyRole`) means a
  routine ZSK can never establish initial trust, roll the KSK over, or (as
  of this session) decommission the zone — those three remain gated to
  `candidateRole == RoleKSK` specifically, checked the same way in each
  case.
- Countermeasure: `decommission-zone`'s authorization is deliberately as
  strict as first contact or a rollover, not merely "any currently
  authorized key" the way `add-zsk`/`retire-zsk` are — removing a zone
  entirely is at least as consequential as establishing or replacing its
  KSK.
- **Gap, previously identified, restated here for completeness**: there is
  no authorization scoping *within* a role. Every registered key, KSK or
  ZSK alike, is authorized to do everything a SIG(0)-authenticated push of
  its tier can do — a ZSK can push content, add or retire *other* ZSKs, and
  manage the contact registration, with no way to restrict a specific
  key (e.g., one automation box's) to a narrower set of operations. A
  compromised ZSK is a meaningfully bad day (arbitrary content, persistent
  ZSK additions for continued access after the original is caught and
  retired) even though it cannot touch the KSK or decommission the zone.

## 10. Summary of identified gaps, ranked by what to address first

1. **Replay of a captured, still-valid push within its one-hour SIG(0)
   window** (§5) — concrete, currently exploitable if a customer's own
   tooling omits `previousSerial`, and unmitigated at all for
   key-management operations regardless of client behavior. The most
   actionable finding in this document; needs a monotonic nonce/sequence
   requirement for key-management ops specifically.
2. **Hardcoded root trust anchor with no rollover mechanism** (§4, §8) —
   a time-delayed, fleet-wide, silent failure waiting for IANA's next root
   KSK rotation. Not urgent today, but worth planning before it becomes
   urgent on someone else's schedule.
3. **Rate limiting is not cluster-aware** (§8) — best addressed before
   `SAZU-CLUSTER.md`'s gossip work goes much further, since retrofitting
   shared quota state after the fact is harder than designing it in.
4. **No per-key authorization scoping** (§9) — already tracked in
   README's Known Limitations; restated here as a real elevation-relevant
   residual risk, not a new finding.
5. **Audit trail has no tamper-evidence or retention policy** (§6, §8) —
   lower severity; worth a retention knob and worth being explicit that
   it's an operational record, not a compliance-grade log.
