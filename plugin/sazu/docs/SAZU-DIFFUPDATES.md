# Differential updates: considered approaches and why none were kept

`publish-zone` always sends a zone's complete, authoritative content —
there is no partial/differential update command, and every change,
however small, is a fresh full push of the whole thing. That's a
deliberate simplification, not an oversight: this project tried three
different differential-update designs across its development, each
working and covered by tests at the time, before concluding none of them
were worth the complexity given the actual size of the zones this
protocol targets (a customer's own domain, typically dozens to a few
hundred records — not a bulk DNS host's multi-million-record zones,
where a full-resend's bandwidth would genuinely matter). All three are
recorded here rather than just deleted from history, so the tradeoff is
visible to anyone tempted to rebuild one of them later.

1. **A local cache on the client**, keyed by zone, recording the last
   pushed NSEC/NSEC3 chain state so `sazuctl` could compute an
   incremental chain patch itself without querying the server first.
   *Advantage:* no extra network round trip before a push. *Disadvantages:*
   the cache is one more piece of state that can silently drift from
   what the server actually has (a manual edit, a restore from backup, a
   second `sazuctl` instance pushing the same zone) — and once it does,
   the client has no way to notice before sending a patch computed
   against a picture that's already wrong. Any of those makes the local
   cache actively unreliable as a source of truth, not just occasionally
   stale.
2. **Live client-side discovery and reconciliation.** Instead of trusting
   a cache, `sazuctl` would query `-target` directly before every push —
   the current SOA, the NSEC/NSEC3 chain, and the actual content at every
   name the zone file or the live chain mentions — diff that live picture
   against the zone file, and send exactly the resulting patch (additions,
   changed values, dropped names/types), guarded by an RFC 2136 §2.4.2
   prerequisite asserting the prior value of everything the diff depended
   on so a picture that went stale mid-computation would be rejected
   outright rather than silently misapplied. *Advantage:* no local state
   to drift; the zone file remained the single source of truth, checked
   fresh every time. *Disadvantages:* real, structural ones, not just
   implementation bugs — an NSEC3 chain only ever reveals hashed owner
   names, so a hash that doesn't happen to match one of the zone file's
   own candidate names can't be resolved back to "which real name should
   be removed" (this is NSEC3's whole privacy property working as
   designed, not a bug to fix); and a naive implementation of this
   approach hit several real correctness bugs along the way — deleting a
   name's content via the wrong RFC 2136 form left an orphaned RRSIG
   behind, a type-level RRset delete swept up other types' unrelated
   RRSIGs, and a §2.4.4 "name is in use" prerequisite sent through the
   wrong builder method silently corrupted its own Class field — each
   fixable individually, but their accumulation was itself a signal that
   the approach carried more surface area for subtle mistakes than the
   size of zone it was solving for justified.
3. **Server-side diffing**, considered but never built: the server, not
   the client, would compute what changed by comparing an incoming push
   against its own current state, sparing the client the discovery round
   trip entirely. *Advantage:* the client-side query-then-diff round trip
   disappears. *Disadvantage:* it moves real computational trust onto the
   server for something the signature scheme doesn't actually need it to
   do — every record's own RRSIG plus the transaction's overall SIG(0)
   already fully authenticate *content*, so having the server additionally
   reconstruct *intent* (what should be added vs. changed vs. removed)
   from a partial push adds a whole second class of logic to get right,
   for a cost (server CPU comparing an incoming push against existing
   state) that's negligible at this protocol's actual scale.

The common thread: every approach above is solving a bandwidth/CPU
problem that a full zone push barely has, at the price of real,
recurring correctness risk (stale caches, hash-blind chains, subtle RFC
2136 form mistakes) that a full push has none of. As long as every
record's RRSIG and the transaction's overall SIG(0) are both valid,
replacing the whole zone is exactly as safe as replacing one record, and
categorically simpler to reason about, test, and audit. If a future
deployment ever needs to push zones large enough that full-resend
bandwidth becomes the actual bottleneck, revisit this section first —
the trade only shifts once the zones being pushed are dramatically
bigger than what this protocol was designed for.
