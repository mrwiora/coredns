# SAZU threat model

Who the parties are, what each can and can't do, and what a compromise of
each means for this implementation. Organized by STRIDE (Spoofing,
Tampering, Repudiation, Information Disclosure, Denial of Service,
Elevation of Privilege). Every countermeasure cited exists in the code;
open gaps are marked **Gap** and collected in §10.

## 1. Actors

- **Zone owner**: owns a domain and holds its KSK and ZSK private keys. The
  server never holds, sees or needs private key material.
- **SAZU operator**: runs CoreDNS with the `sazu` plugin, and optionally
  `sazu-watchd`. Often a hosting provider serving many owners.
- **Registrar**: holds the parent-zone delegation and DS record. Outside
  SAZU's control; SAZU only reads it.
- **DNS root and TLD infrastructure**: what `VerifyChainOfTrust` walks to
  confirm a DS exists at the parent.
- **Resolvers**: validating resolvers check RRSIGs; non-validating ones
  don't (see §5).
- **Attacker**: on-path or off-path (spoofing), without legitimate keys.
- **Partner instance** (once `SAZU-CLUSTER.md` is built): another SAZU
  process in the same replication group.

## 2. Assets

- Zone content and its DNSSEC signatures (public once served; integrity
  and availability matter).
- Each zone's apex DNSKEY RRset (public keys only).
- The zone's control state: the version counter and any pending KSK
  rollover.
- The contact registration (never served as DNS content).
- The audit trail (`audit_log`).
- The SAZU host and process (protected by the operator, not by SAZU; see §3).

## 3. Trust boundaries

- **Owner ↔ server**: RFC 2136 UPDATE over TCP, UDP (not for onboarding
  or KSK rollover) or DNS over HTTPS, authenticated by SIG(0) (RFC 2931)
  with the zone's own keys.
- **Server ↔ registrar**: none directly. The DS is read with ordinary DNS
  queries during the chain-of-trust walk, whose DNSSEC validation makes
  the unauthenticated hops safe.
- **Server ↔ root/TLD**: DNS queries validated against the root trust
  anchors (built in, or a maintained `trust_anchor` file).
- **Server ↔ resolver**: ordinary DNS, authenticated by the owner's RRSIGs
  for resolvers that validate.
- **Server ↔ host filesystem**: the SQLite `db` file. Its confidentiality
  and integrity rest on host access control, **outside SAZU's scope**.
- **Instance ↔ instance** (future): the cluster's authenticated channel,
  see `SAZU-CLUSTER.md`.

## 4. Spoofing

**Threat: someone who doesn't control a domain onboards it or pushes
content for it.**

- Every UPDATE is authenticated by SIG(0), verified against the zone's
  registered keys (`VerifySIG0`) over the exact bytes received; only the
  message parsed from those verified bytes is processed, so a spoofed
  packet can't pair its own content with someone else's signature. The
  SIG(0) signer name must be the zone apex.
- First contact and KSK rollover also require the candidate KSK to match a
  DS at the real parent: `VerifyChainOfTrust` walks from the root trust
  anchor down, requiring each DNSKEY RRset to be signed by an anchored or
  DS-matched key (RFC 4035 §5.2) and accepting only SHA-256/SHA-384 DS
  digests. Generating a key and self-signing is not enough; the attacker
  would also need the registrar-level delegation.
- A candidate key below the RFC 8624 algorithm floor is refused before any
  signature or network work (`algorithmMeetsFloor`).
- Onboarding and KSK rollover are refused over UDP, where the source
  address isn't validated (`ERR_TRANSPORT_NOT_ALLOWED`).

**Threat: someone who takes over the registrar account rolls the zone to
their own KSK.** A rollover proven only by a new key and its DS is held
as pending for `rollover_hold_down` (default 72 h); `sazu-watchd` alerts
the contact, and any control change by the current KSK — including
`sazuctl cancel-rollover` — cancels it. A rollover co-signed by the
current KSK applies at once. An owner who still holds the KSK therefore
can't lose the zone to a registrar compromise without being alerted with
time to act. (Specification §8.2, §12.2.)

## 5. Tampering

**Threat: a push is modified in transit, or carries content its sender
didn't sign.**

- Content-signature verification is mandatory and can't be disabled
  (`VerifySignedRRsetsSplit`): every authoritative RRset needs a valid
  RRSIG from a key allowed to sign it — the DNSKEY RRset from the KSK
  only, other RRsets from the KSK or a registered ZSK — and every RRSIG
  in the push must itself verify. SIG(0) proves who sent the push; the
  RRSIGs prove what resolvers will accept.
- A change to the DNSKEY RRset must carry the complete resulting RRset,
  signed by the KSK, and it must equal the pinned KSK plus the registered
  ZSKs.
- Content changes are full-zone replacements only, so a push can't leave
  the denial-of-existence chain describing content that no longer exists.
- A push that isn't a valid zone (RFC 2181 §5.2/§10.1, RFC 6672 §2.4) is
  refused.

**Threat: someone with access to the host's `db` file changes stored
content.**

- A validating resolver rejects it: the attacker can't make new RRSIGs
  without the owner's private keys, which the server never holds.
- **Gap**: a non-validating resolver accepts it. This is inherent to DNSSEC,
  not specific to SAZU.
- **Gap (operator scope)**: access control for the `db` file and the
  process is the operator's responsibility.

**Threat: a captured push is replayed to revert a zone.**

- Content pushes must raise the SOA serial (RFC 1982), so an older one
  never lands over a newer one.
- Every control change (onboarding, KSK rollover, a DNSKEY RRset change, a
  contact change, cancelling a rollover, decommission) and a zone's first
  content push must name the zone's current version in an RFC 2136
  §2.4.2 prerequisite, and increments it. A captured control message is
  valid for exactly one version: it can't apply twice or out of order,
  whatever any clock says. The version is part of the zone's state,
  survives decommission, and would replicate with the zone.
- A SIG(0) validity window is capped at `max_sig0_lifetime` (default
  1h5m).

## 6. Repudiation

- The audit trail records every transaction, accepted or rejected, with
  the key tag and role that authenticated it (`AuditEntry`), so with
  several ZSKs it shows which signer pushed what. A decommissioned zone's
  audit rows are kept.
- **Gap**: the audit trail isn't tamper-evident — no hash chaining,
  append-only enforcement or external attestation. Anyone with write
  access to the `db` file can change it. It is an operational record, not
  a compliance-grade log.

## 7. Information disclosure

- The contact registration is stripped from a push before it is treated
  as zone content (`splitContactOps`) and never served.
- Zone content is public DNS data. With NSEC3 (the `sazuctl` default) the
  zone's names aren't trivially enumerable; with NSEC they are.
- **Gap (operator scope)**: the `db` file, including the audit trail's
  source addresses, has only file-permission protection.

## 8. Denial of service

- `IPRateLimiter` caps UPDATE attempts per source address (IPv6 per /64)
  before any signature work.
- `RateLimiter`'s per-zone quotas (content and key management, separately)
  bound authenticated churn, checked before the chain-of-trust walk.
- Onboarding and KSK rollover — the operations that trigger outbound
  queries — are refused over UDP, so spoofed addresses can't evade the
  per-address limit.
- Both limiters sweep their state, so memory tracks recently active
  sources, not every source ever seen. The raw-capture table is bounded,
  holds only UPDATEs, and every UPDATE claims its entry on arrival.
- ANY over UDP is answered with one RRset (RFC 8482), limiting
  amplification.
- **Gap**: the limiters are per process and in memory; several instances
  (`SAZU-CLUSTER.md`) would multiply every quota by the instance count.
- **Gap**: `audit_log` has no retention policy and grows without bound.
- **Operational risk**: a stale root trust anchor fails closed — onboarding
  and rollover stop for every zone at once after a root KSK rollover. Use
  a `trust_anchor` file kept current (e.g. by `unbound-anchor`).

## 9. Elevation of privilege

- The KSK/ZSK split (`keys.go`): only the KSK can establish trust, roll
  over, sign the DNSKEY RRset, add or retire ZSKs, change the contact,
  cancel a rollover or decommission the zone. A ZSK can push content and
  nothing else, so a stolen ZSK can be retired with one KSK-signed update
  and can't lock the owner out first.
- `sazu-watchd` delivers webhooks only to public addresses (checked at
  dial time, no redirects, no proxy) unless `-webhook-allow-private`, so a
  zone owner can't aim it at the operator's internal network.
- **Gap (by design)**: every ZSK may push content for the whole zone.
  Narrower authority is expressed by delegating a subzone with its own
  keys (specification §13.4).

## 10. Open gaps, by priority

1. **Rate limiting is not cluster-aware** (§8) — to be designed into
   `SAZU-CLUSTER.md` before it is built.
2. **Audit trail has no tamper evidence or retention policy** (§6, §8).
3. **Operator-scope boundaries** (§5, §7): host access control for the
   `db` file and process, and host time synchronization (SIG(0) and RRSIG
   validity are checked against the server's clock).
