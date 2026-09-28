# Differential updates: alternatives to full-zone pushes

`publish-zone` always sends a zone's complete, authoritative content.
There is no partial or differential update: every change, however small,
is a full push (specification §5.3, §13.2). SAZU targets an owner's own
domains — typically dozens to a few hundred records — where resending the
whole zone costs little. These are the alternatives, and why none of them
is used.

1. **A client-side cache** of the last pushed zone and denial chain, so
   `sazuctl` can compute an incremental patch without asking the server.
   *Advantage:* no extra round trip. *Disadvantage:* the cache drifts from
   what the server serves (a manual change, a restore from backup, a second
   client pushing the same zone), and the client cannot notice before it
   sends a patch computed against the wrong picture.
2. **Client-side discovery.** `sazuctl` queries the server before every
   push — the SOA, the denial chain and the content at every name the zone
   file or the chain mentions — diffs that against the zone file, and sends
   the patch guarded by RFC 2136 §2.4.2 prerequisites on everything the
   diff depended on. *Advantage:* no local state; the zone file stays the
   source of truth. *Disadvantages:* an NSEC3 chain reveals only hashed
   names, so a hash that matches none of the zone file's names can't be
   mapped back to the name to remove (NSEC3's privacy property working as
   designed). And a patch is a sequence of RFC 2136 add, delete-RR,
   delete-RRset and delete-name operations whose RRSIG and denial-chain
   bookkeeping must be exactly right — much more surface for subtle
   mistakes than replacing the zone.
3. **Server-side diffing.** The server compares an incoming zone with its
   current state. *Advantage:* no discovery round trip. *Disadvantage:* the
   RRSIGs and SIG(0) already authenticate the content; having the server
   also work out the owner's intent (add, change or remove) is a second
   body of logic to get right, to save a cost that is negligible at this
   scale.

Each alternative saves bandwidth or CPU that a full push barely spends, at
the price of correctness risk a full push doesn't have. As long as every
RRSIG and the SIG(0) are valid, replacing the whole zone is as safe as
replacing one record, and simpler to reason about, test and audit. The
trade-off changes only for zones far larger than SAZU is designed for.
