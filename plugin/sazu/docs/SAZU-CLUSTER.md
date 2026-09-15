# SAZU cluster replication: specification

This is the decided design for running more than one SAZU-enabled CoreDNS
instance for the same set of zones, converged automatically. This document
states the result as a defined design, not a narrative of how it was
reached.

**Status: deferred.** Nothing in this document beyond `decommission-zone`
(§5) is implemented yet. This is the specification to build from when work
resumes, not a report of work done.

**Alternatives considered and rejected along the way**, kept here briefly
so they aren't relitigated from scratch later:

- **Directional `replicate_to`/`sync_from` configuration**, distinguishing
  which instance pushes to which and which pulls from which. Rejected for
  the symmetric `partners` list (§2): a directional scheme means every
  instance's Corefile encodes its specific role relative to every other
  instance, and adding one more instance means revisiting all of them.
- **mTLS between instances** (per-instance client certificates, verified
  against a shared CA). Rejected in favor of the cluster secret (§4): mTLS
  would need real PKI/certificate lifecycle management for a benefit the
  AEAD-sealed cluster secret already provides (confidentiality and peer
  authenticity) without it. The one thing mTLS uniquely offers -- distinct
  per-partner identity, since a single shared secret can't tell which
  partner sent a given message -- was judged not worth that operational
  cost for this design; revisit if per-partner identity/revocation turns
  out to matter more than expected in practice.
- **A dedicated cluster port**, then **reusing the HTTPS/DoH carrier**,
  before settling on plain DNS-over-TCP (§3). A dedicated port needs a
  second listener with its own lifecycle; the HTTPS/DoH carrier drags in
  HTTP semantics (POST bodies, content types, a JSON envelope option) that
  buy nothing for server-to-server traffic and, worse, would make gossip
  depend on an operator having configured DoH at all -- plenty of real
  deployments run plain DNS only. Reserved-name DNS messages over the
  existing plain listener need no new listener and no such dependency.

## 1. Overview

Every SAZU instance in a group runs identical, symmetric configuration
naming every other instance ("partner"). Each instance periodically asks
every partner what it currently has for every zone it knows about, and
reconciles: whichever side is behind a given zone's state pulls the
complete current signed content from whichever side is ahead. A freshly
started instance's first round of this is how it catches up; every
instance's every later round is how a real push propagates. There is one
mechanism, not two.

## 2. Configuration

```
sazu . {
    db /var/lib/sazu/sazu.db
    partners 10.0.1.11:5391 10.0.1.12:5391
    cluster_secret_file /etc/sazu/cluster.secret
}
```

- `partners host:port...` -- every other instance in the group. No
  instance is distinguished as a source of truth; the same directive,
  minus itself, appears in every instance's Corefile.
- `cluster_secret_file PATH` -- a pre-shared secret, loaded from a file
  the same way `-key-passphrase-file` already is elsewhere in this
  project. Required for any gossip to take place; an instance with no
  secret configured does not participate in a group at all (see §4).
- Both are optional at the plugin level: an instance with neither
  configured behaves exactly as a single, standalone instance does today.

## 3. Transport

Gossip messages are ordinary DNS QUERY/UPDATE messages at reserved owner
names, riding the plain `dns://` TCP listener every instance already runs
-- no new port, no new listener, no HTTP or TLS anywhere in the path. TCP
specifically, not UDP: a full zone snapshot routinely exceeds one UDP
datagram.

- **Digest exchange**: a QUERY for `_sazu-digest.<zone>` TXT, answered by
  `serveQuery`. The TXT payload is the AEAD-sealed digest (§4).
- **Snapshot pull**: a QUERY/UPDATE pair at a similarly reserved name,
  carrying the AEAD-sealed complete current zone state. Exact wire shape
  (one large answer vs. several successive queries vs. an UPDATE-shaped
  push in the pull direction) is not fixed by this document -- decide at
  implementation time based on how large a real snapshot needs to be.

## 4. The cluster secret and payload encryption

Every gossip message's payload is sealed with a symmetric AEAD key derived
from the cluster secret (HKDF-SHA256 over the secret, then AES-256-GCM or
ChaCha20-Poly1305). This gives:

- **Confidentiality**: an observer on the network can't see which zones
  exist in the group, their digests, or pulled content.
- **Authenticity**: a party without the secret can't construct anything
  that decrypts, so it can neither answer a digest request convincingly
  nor inject a fabricated "I have newer state" claim.

This is a transport-layer protection on who can meaningfully participate
in gossip. It is layered on top of, and never a substitute for, SIG(0)/
RRSIG content verification: every pulled zone's RRSIGs are independently
re-verified against the chain of trust by the receiving instance, exactly
as for a direct customer push. Holding the cluster secret lets an instance
participate in the group; it does not let it forge zone content a customer
never actually signed.

An instance with no `cluster_secret_file` configured does not gossip at
all, regardless of whether `partners` is set -- there is no unauthenticated
fallback mode.

## 5. Zone removal: decommissioning and tombstones

**`sazuctl decommission-zone` is implemented today** (`decommission.go`,
`push.go`'s `BuildDecommissionPush`, `handler.go`, `DB.DeleteZone`) and
needs no further work for single-instance use: it removes a zone's KSK,
every ZSK, all content and its chain, and its contact registration,
authenticated by the zone's own KSK specifically, requiring an explicit
`-yes` confirmation from the CLI.

**What's not yet built is propagating that removal through gossip
correctly.** Naively letting an instance simply go quiet about a
decommissioned zone would let gossip resurrect it: digest comparison alone
can't distinguish "I've never heard of this zone" from "I used to have it
and it was legitimately removed." The fix is a tombstone:

- When a zone is decommissioned, an instance replaces its live digest for
  that zone with a tombstone: a small marker recording that the zone was
  decommissioned, when, and a reference to the KSK-signed decommission
  transaction that did it.
- A tombstone always beats an older live digest for the same zone in
  gossip comparison -- a partner offering live content for a tombstoned
  zone is told to delete it too.
- A live digest *newer* than the tombstone still wins -- the same zone
  name legitimately re-onboarded later (necessarily with a new KSK, since
  the old one was removed) supersedes the tombstone, the same way a KSK
  rollover's new key supersedes its predecessor.
- Tombstones are garbage-collected after a configurable `tombstone_ttl`
  (days, not minutes -- long enough to outlast the gossip interval times
  the group's diameter, plus margin for a partition to heal). An instance
  partitioned away longer than the TTL can resurrect a decommissioned zone
  on rejoining; this is bounded by the TTL, not eliminated by it, and is
  worth a `sazu-watchd` alert rather than a claim that it can't happen.

## 6. The gossip round

For each zone an instance has (or has heard a partner mention), it
maintains a state digest: a keyed hash over the zone name, its current SOA
serial, the sorted set of currently registered DNSKEY key tags, and a hash
of its current signed content (or, per §5, a tombstone marker in place of
a live digest). Anything that changes the zone's real state changes this
digest; nothing else does.

Each round, for every partner:

1. Ask for its digest of every zone it has.
2. For any zone with a **different** digest on either side (including one
   side never having heard of it at all), the side that's behind pulls
   that zone's complete current signed state from the side that's ahead.
   "Ahead" means the higher SOA serial ordinarily, or the DNSKEY-key-tag
   component of the digest for a key-management-only change with no SOA
   bump, or a tombstone beating an older live digest per §5.
3. The pulled state is applied locally exactly the way `LoadAll` already
   hydrates a fresh `Store`/`KeyRegistry` from a local `db` file at
   startup -- just from a network source. Every RRSIG in it is
   independently re-verified against the chain of trust (§4).
4. Matching digests: no-op. This is the common case in a converged group.

An instance may also announce its own fresh digest to every partner
immediately after committing a real customer push, ahead of the next
periodic round, purely to cut propagation latency. This is an optimization
on the mechanism above, not a separate one.

**No explicit loop-prevention rule is needed.** This is convergent, not
propagating: an instance only acts when it sees a digest genuinely
different from what it already has. Once a group agrees, every further
comparison is a no-op, so there's no message left to keep circulating. The
worst case during convergence is a bounded burst of redundant
announcements, not an unbounded loop.

## 7. Consistency model

Eventually consistent, not transactional, on the order of one gossip
interval. Two pushes to two different instances for the same zone in a
short window converge on whichever has the higher SOA serial once digests
are compared -- the same last-write-wins behavior a single instance
already has for two closely-spaced pushes, just eventual across instances
instead of immediate on one.

## 8. What doesn't change

- **The zone file is identical across every instance and is pushed
  exactly once**, to whichever single instance the customer's `sazuctl`
  is pointed at. Distribution is instance-to-instance, invisible to the
  customer. A zone's SOA `MNAME` and NS records are ordinary customer
  content, unaffected by how many instances exist behind the delegation
  -- SAZU has no AXFR/IXFR primary/secondary concept for `MNAME` to drive.
- **SIG(0)/RRSIG content verification is unchanged and independent per
  instance.** Gossip and the cluster secret govern who participates in
  the conversation; they never substitute for a customer's own signature
  on the content itself.

## 9. Implementation order

1. Tombstone data structure and storage, built on §5's already-implemented
   `decommission-zone`.
2. `cluster_secret_file` config loading and the AEAD seal/open primitives
   (§4).
3. Per-zone state digest computation (§6).
4. `partners` config, and the reserved-name digest-exchange and
   snapshot-pull messages (§3), including the exact snapshot wire shape
   left open in §3.
5. The background gossip loop itself: periodic round, comparison, pull,
   apply, plus the optional eager-announce-on-commit optimization.
6. `sazu-watchd` awareness of instances whose digests have stopped
   matching the group, or that have become unreachable for gossip
   entirely, and of the tombstone-TTL resurrection risk noted in §5.

## 10. Open questions carried over from the concept doc

- Gossip interval tuning (fixed period vs. backoff vs. jitter across a
  large group).
- Exact digest construction details (field set, hash choice).
- Fencing/leader election to prevent two instances accepting conflicting
  pushes for the same zone at once, rather than just converging after the
  fact -- not designed here, only noted as a possible future need.
- Cluster-secret rotation without a flag-day (accepting two active
  secrets during a rollover window).
