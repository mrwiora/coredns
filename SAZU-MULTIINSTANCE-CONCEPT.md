# SAZU multi-instance concept: partner replication and startup sync

A theoretical design sketch, not yet implemented. This is what it would take to
run more than one SAZU-enabled CoreDNS instance for the same set of zones,
each one accepting a real customer push and automatically distributing it to
its partner instance(s), without risking a circular replication loop, and
with a way for a freshly started instance to catch up on state it missed.

## The problem

Today, one SAZU instance is the whole story: a customer's `sazuctl` push goes
to exactly one server, and that server is the only place the zone's state
lives (in memory, and in `db PATH` if configured). Running two or more
instances behind the same delegation (e.g. `ns1.example.org.`/
`ns2.example.org.`) means either:

- the customer pushes to every instance separately (real, and the obvious
  approach, but pushes the multi-instance problem onto every customer's own
  tooling/scripting instead of solving it once, centrally), or
- one instance accepts the push and distributes it to the others itself.

This document is about the second approach.

## Design principle: a flat, symmetric partner list -- no direction, no roles

Earlier drafts of this design had directional configuration --
`replicate_to` (push my updates outward) on one side, `sync_from` (pull
state on startup) on the other -- which meant every instance's Corefile had
to encode which role it played relative to every other instance, and adding
a third instance meant revisiting all of them.

That direction isn't actually needed. Every instance can carry the exact
same, symmetric configuration:

```
sazu . {
    db /var/lib/sazu/sazu.db
    partners 10.0.1.11:5391 10.0.1.12:5391
    cluster_secret_file /etc/sazu/cluster.secret
}
```

`partners` just lists every other instance in the group -- no instance is
special, no instance is "the" source of truth, and there is no separate
first-boot-only sync step. Every instance, all the time, periodically asks
every partner it knows about **"what do you currently have for the zones you
know about?"** and reconciles based on the answer. A freshly started
instance's very first round of that is what used to be called "sync"; an
already-running instance's every subsequent round is what used to be called
"replication." They're the same mechanism, run continuously, not two
different mechanisms glued together.

## How the gossip round works

For each zone an instance currently has (or has heard a partner mention), it
maintains a small **state digest**: a fixed-size value summarizing "what
this zone's current, complete state is" -- cheap enough to exchange
constantly, without ever transmitting full zone content unless something
has actually changed. A reasonable shape for it: a keyed hash (see the
cluster-secret section below) over the zone name, its current SOA serial,
the sorted set of currently registered DNSKEY key tags, and a hash of its
current signed content -- anything that changes the zone's real state
changes this digest; nothing else does.

Each gossip round, for every partner:

1. Ask for its current digest of every zone it has.
2. For any zone name appearing on either side with a **different** digest
   (including a zone one side has never heard of at all), the side that's
   behind pulls that zone's complete current signed state from the side
   that's ahead -- "ahead" ordinarily meaning the higher SOA serial (already
   monotonic, by the same discipline `previousSerial` already assumes on a
   single instance); a key-management-only change with no SOA bump is
   detected the same way through the DNSKEY-key-tag component of the digest.
3. The pulled state -- apex DNSKEY RRset, zone content, NSEC/NSEC3 chain,
   all already signed -- is applied locally exactly the way `LoadAll`
   already hydrates a fresh `Store`/`KeyRegistry` from a local `db` file at
   startup, just from a network source instead of a local one. Every RRSIG
   in it is independently re-verified against the chain of trust this
   instance already knows (or, for a zone it's never seen at all, the same
   first-contact chain-of-trust walk a real `publish-trust` triggers) --
   the gossip exchange authenticates *the peer relationship* (below);
   content signatures still authenticate *the content itself*, exactly as
   for a direct customer push. Neither replaces the other.
4. Digests match: nothing happens. This is the common case in a converged
   group, which is most of the time -- gossip rounds cost almost nothing
   once every instance already agrees.

An instance can also announce its own fresh digest to every partner
immediately after committing a real customer push, rather than waiting for
the next periodic round, purely to cut propagation latency -- this is an
optional optimization on top of the mechanism above, not a separate one:
it's the exact same "compare digest, pull if behind" logic, just triggered
early instead of on a timer.

## Why this doesn't need a loop-prevention rule at all

Earlier drafts needed an explicit rule ("never re-forward something
received via the peer channel") because blind store-and-forward relaying
has no natural stopping point -- a message can circulate forever unless
something is added to stop it.

Gossip-by-comparison doesn't have that failure mode, because it's
**convergent, not propagating**: an instance only ever *does* anything (pull
+ re-announce) when it observes a digest that's genuinely different from
what it already has. Once every instance in the group has pulled the same
state, every subsequent digest comparison between any pair of them comes
back equal, and nothing happens -- there's no message left that keeps
circulating, because "the same state, again" isn't news to anyone anymore.
A change genuinely propagates outward from wherever it originated, reaches
every instance in the group, and then the gossip traffic about it stops on
its own. The worst case during convergence is a bounded burst of redundant
"did you know?" announcements (at most on the order of one per instance
pair, for one real change) -- not an unbounded loop -- and even that's easy
to damp further with a small per-zone announce debounce if it matters at
the group sizes this is ever likely to run at.

## The cluster secret: symmetric authenticated encryption, not just a hash

The gossip exchange needs the participating instances to authenticate *each
other* -- content signatures alone don't prevent a non-partner from
learning which zones exist, what their current digests are, or (worse)
answering a digest request with a stale-but-validly-signed rollback
snapshot for a zone it isn't actually part of this group for.

A single pre-shared **cluster secret**, loaded from a file the same way
`-key-passphrase-file` already is elsewhere in this project (never written
inline in the Corefile), is the appropriately-sized answer -- no
certificate lifecycle, no PKI, one value every legitimate instance in the
group is configured with.

Rather than only keying a plain hash (HMAC gives authenticity -- "this
digest genuinely came from a holder of the secret, unmodified in transit"
-- but leaves the digest and zone name visible to anything that can observe
the traffic), derive a symmetric **AEAD** key from the cluster secret
(HKDF-SHA256 over the secret is enough) and use it to encrypt the entire
gossip payload -- AES-256-GCM or ChaCha20-Poly1305, either gives both
properties in one primitive:

- **Confidentiality**: an observer on the network between two instances
  can't see which zones exist in the group, their digests, or any pulled
  content -- just an opaque authenticated blob.
- **Authenticity/integrity**: a party without the secret can't construct a
  payload that decrypts to anything at all, so it can neither answer a
  digest request convincingly nor inject a fabricated "I have newer state"
  announcement. AEAD's built-in authentication tag catches tampering the
  same way it catches forgery.

This is a transport-layer protection on the partner channel -- who can
meaningfully participate in gossip at all, and keeping that traffic private
from anything else on the network -- layered *on top of*, never instead of,
the existing SIG(0)/RRSIG content authentication every pulled zone state
still goes through independently. Holding the cluster secret lets an
instance participate in the group; it does not, by itself, let it forge
zone content a customer never actually signed.

## Transport: plain DNS-over-TCP, nothing else

Gossip messages ride as ordinary DNS QUERY/UPDATE-shaped messages at
reserved owner names, the exact same convention `contact.go` already uses
for the §10.6 registration-contact record (`_sazu-contact.<zone>`, a TXT
RRset carried inside an otherwise ordinary authenticated push, never itself
zone content). A digest exchange becomes a QUERY for e.g.
`_sazu-digest.<zone>` TXT, answered directly by `serveQuery`; a snapshot
pull becomes a QUERY/UPDATE pair at a similarly reserved name.

Because these are just DNS messages like any other, they need **no new
carrier at all** -- they ride over TCP on the same plain `dns://` listener
every SAZU instance already runs for customer pushes and queries. No new
port, no new listener, no HTTP semantics anywhere in the path: a partner is
simply another client of that same listener, distinguished only by which
reserved names it's asking about and by the cluster-secret-encrypted
payload those messages carry (see the section above) -- never by transport.

TCP specifically, not UDP, for the same reason `sazuctl` already forces TCP
for anything non-trivial: a full zone snapshot (the complete DNSKEY RRset,
all content, every RRSIG, the NSEC/NSEC3 chain) routinely exceeds what one
UDP datagram can safely carry, and a truncated or dropped snapshot mid-pull
is a worse failure mode than the one extra round trip TCP's handshake
costs.

## Does the zone file need to look different per server?

**No -- it is the exact same file, and the customer only ever pushes it
once.** This falls directly out of the design above, not as an extra
consideration bolted on afterward:

- Distribution happens **instance-to-instance**, after a single customer
  push lands on whichever one instance the customer's `sazuctl` is pointed
  at. The customer never pushes to more than one server, and never needs
  to know how many partner instances exist behind it, or how they're wired
  together.
- Because gossip pulls the *actual current signed state* -- the same
  DNSKEY RRset, content, and RRSIGs the originating instance has -- rather
  than each instance re-deriving or re-signing anything of its own, every
  instance that converges ends up with byte-identical zone content. There
  is no per-instance customization step for the content itself to go
  through.
- The zone file's own SOA `MNAME` field (conventionally "the primary
  server's name," in classic AXFR-based DNS) and its NS records are
  ordinary, customer-authored zone content like everything else -- they
  describe the zone to the outside world once, the same way regardless of
  which specific instance a resolver happens to ask. SAZU has no AXFR/IXFR
  zone-transfer concept for `MNAME` to drive (there is no "primary pulls,
  secondaries push" relationship here, symmetric or otherwise), so `MNAME`
  is purely informational in this design, same as it already is today with
  a single instance -- nothing about running multiple instances changes
  what a customer would ever write into that field.

What *does* need to differ per instance is Corefile-level, never the zone
file: each instance's own `partners` list (which, being symmetric, can
often just be "everyone else in the group, minus myself"), its own `db`
path, and whichever port/zone-scope it listens on. None of that is content
a customer's zone file or `sazuctl` invocation ever needs to express.

## Consistency model and the one real tradeoff

This is eventually consistent, not transactional, across instances, on the
order of one gossip interval (whatever that's tuned to -- seconds, if an
eager announce-on-commit is used; the plain periodic interval otherwise).
If a customer (or two different automation boxes with independently valid
ZSKs -- see the KSK/ZSK multi-signer design) pushed to two different
instances for the *same* zone in a short window, each instance keeps
whichever push it received directly until the next gossip round, and the
group converges on whichever has the higher SOA serial once digests are
compared -- exactly the same last-write-wins behavior a single instance
already has for two closely-spaced pushes, just eventual across instances
instead of immediate on one.

Nothing about this design changes SAZU's core trust model: every instance
still independently verifies every push's SIG(0) and content signatures.
Gossip only ever moves already-authenticated, already-signed state between
instances that would each, independently, accept it anyway if a customer
had sent it there directly -- the cluster secret governs who gets to
participate in that conversation, not what content is trusted once pulled.

## Removing a zone from the cluster: decommissioning and tombstones

Getting rid of a stale zone across the whole group turns out to need two
things this design doesn't have yet: a way to remove a zone at all, and a
way for that removal to survive gossip rather than being silently undone by
it.

**There is currently no "remove a zone" operation, single-instance or
not.** Every existing delete-shaped operation in this codebase deliberately
protects the apex SOA -- `ZoneData.deleteRRsetLocked`'s own comment is
explicit: *"a zone's SOA is never removable this way, only replaced."*
Nothing in `handler.go`/`push.go` today lets an authenticated push say "this
zone is gone," and that has to exist before a cluster can agree on it. The
natural shape, matching every other key-management operation here: a new
`sazuctl decommission-zone -zone <zone> -ksk-key <path> -target ...`,
authenticated by the KSK specifically (this is at least as consequential as
a rollover, arguably more so), that tells the receiving instance to drop
the zone's KSK, every registered ZSK, all content, its NSEC/NSEC3 chain,
and its registration/contact record -- from `Store`, `KeyRegistry`,
`Contacts`, and `db` alike. As with a KSK rollover, this says nothing about
the parent DS record -- removing that at the registrar stays the customer's
own out-of-band step, the same way publishing one always has been.

**Naively deleting it locally is actively wrong once gossip is in the
picture.** Digest comparison as designed so far can't tell "I've never
heard of this zone" from "I used to have this zone and it was legitimately
decommissioned" -- both look like "I have nothing to say about zone X."
Left alone, that ambiguity means gossip would **resurrect** every
decommissioned zone: the instance that processed the decommission goes
quiet about it, a partner that hasn't caught up yet still has the old
digest, and on the next round that partner looks "ahead" and re-populates
the zone right back onto the instance that just correctly deleted it. This
is a well-known failure mode in every gossip/anti-entropy system that
doesn't specifically guard against it (Cassandra and DynamoDB both hit
exactly this and both fix it the same way).

**The standard fix is a tombstone, not a deletion.** When a zone is
decommissioned, an instance doesn't erase its record of it -- it replaces
the live state with a small marker: *"zone X was decommissioned, at
[timestamp], authenticated by [a reference to the KSK-signed
decommission push]."* This tombstone gets its own digest and takes part in
gossip exactly like a live zone's digest does, with one added rule:

- A tombstone always beats an older live digest for the same zone -- a
  partner offering "here's zone X's content" for a zone you hold a
  tombstone for gets told to delete it too, the same directional pull the
  live-content case already uses, just carrying "forget this" instead of
  "here's fresh state."
- A live digest **newer than the tombstone** still wins over it -- if the
  same zone name is legitimately re-onboarded later (a fresh
  `publish-trust`, necessarily with a new KSK, since the old one was
  retired along with everything else), that's real new state and
  supersedes the old tombstone exactly the way a KSK rollover's new key
  already supersedes its predecessor. Existence is just one more thing
  timestamp/serial ordering already has to arbitrate.

**Tombstones need their own garbage collection**, or they'd just replace
one kind of unbounded, never-cleaned state with another. Once every
instance in the group has demonstrably seen a tombstone -- or, simpler and
good enough in practice, once a configurable `tombstone_ttl` (long enough
to comfortably outlast the gossip interval times the group's diameter, plus
margin for a partition to heal -- days, not minutes) has passed -- it can be
forgotten for good.

**The one real, inherent tradeoff, worth stating plainly rather than
glossing over:** an instance partitioned away from the group for *longer*
than `tombstone_ttl` can rejoin after every other instance has already
garbage-collected the tombstone, still holding the old live zone, and
resurrect it. Every tombstone-based system has this same edge, bounded by
the TTL rather than eliminated by it -- worth a `sazu-watchd`-level alert
("an instance just re-announced a zone with no other instance holding any
record of it, live or tombstoned") rather than a claim that it can't
happen.

## Open questions / explicitly out of scope here

- Gossip interval tuning (a fixed period vs. exponential backoff against
  an unreachable partner vs. some jitter to avoid every instance in a large
  group polling in lockstep).
- The exact digest construction (which fields feed it, and whether SHA-256
  over a canonical encoding is sufficient, or something more
  structure-aware is worth it) -- sketched above only at the level of "a
  keyed hash over the zone's defining state," not designed in detail.
- The exact reserved-name wire encoding for a snapshot pull -- a digest
  fits comfortably in one TXT answer, but a full zone snapshot (every
  RRset, every RRSIG, the whole DNSKEY set and chain) is a different shape
  of payload; whether that's one large enough answer, several successive
  queries, or an UPDATE-shaped push in the other direction isn't decided
  here.
- Fencing or leader election to prevent the two-instances-accepting-
  conflicting-pushes-at-once race entirely, rather than just converging
  after the fact, if that turns out to matter in practice.
- Cluster-secret rotation without a flag-day (accepting two active secrets
  during a rollover window, the way a TSIG key rotation typically would).
- Whether `sazu-watchd` should also become partner-aware (e.g. alerting on
  an instance whose digests have stopped matching the group, or that's
  become unreachable for gossip entirely), separate from its existing
  chain-of-trust and ZSK-presence checks.
