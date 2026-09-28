# sazu

## Name

*sazu* - accepts DNSSEC-signed zones pushed by their owners as SIG(0)-authenticated RFC 2136 UPDATEs
(SAZU, Self-Authenticated Zone Update), and serves them without holding any private key.

## Description

A zone's owner signs the zone offline and pushes the complete signed zone as one RFC 2136 UPDATE,
authenticated with SIG(0) (RFC 2931) by the zone's own DNSSEC keys. The *sazu* plugin verifies the
transaction signature and every RRSIG in it, then replaces the zone it serves. It never signs
anything. The protocol is specified in `readme.md` of
[github.com/mrwiora/sazu](https://github.com/mrwiora/sazu/blob/main/readme.md); this plugin
implements it as a single server.

There are no accounts or shared secrets. A zone is onboarded by its first UPDATE, which carries
the zone's DNSKEY RRset signed by its KSK: the plugin validates the chain of trust from the root
down to the parent's DS RRset and pins the KSK if one DS matches. From then on:

* the KSK alone changes the zone's DNSKEY RRset (adding and retiring ZSKs, rolling itself over),
  its contact address, and removes the zone;
* a ZSK only pushes content, always the complete zone, with an NSEC or NSEC3 chain;
* content pushes must raise the SOA serial, and control changes must name the zone's current
  version (published unsigned at `_sazu-version.<zone>`), so a captured message can't be
  replayed;
* a KSK rollover proven only by a DS at the parent, without the current KSK's co-signature,
  waits out a hold-down during which the current KSK can cancel it.

Zones are served through the *file* plugin's authoritative lookup over the pushed data: wildcards,
CNAME and DNAME, delegations with glue, DS, and the NSEC or NSEC3 proofs the owner pushed. The
plugin implements the *transfer* plugin's interface, so onboarded zones can be transferred (AXFR,
and IXFR by AXFR fallback) and secondaries are sent NOTIFY after every change. The *cache* plugin
bypasses the plugin's zones, so an acknowledged push is served at once.

UPDATEs are accepted over UDP, TCP, DNS over TLS, HTTPS, HTTP/3 and QUIC; onboarding and KSK
rollover are refused over UDP. Every refusal carries an RFC 8914 Extended DNS Error naming a SAZU
status code (e.g. `ERR_NO_DS_PUBLISHED`).

The client, `sazuctl`, and the monitor that alerts zone owners, `sazu-watchd`, are in `cmd/`. See
[`docs/SAZU-GUIDE.md`](docs/SAZU-GUIDE.md) for building, onboarding a zone, key management and
monitoring.

This plugin is a proof of concept for evaluating the protocol.

## Syntax

~~~ txt
sazu [ZONES...] {
    db PATH
    trust_anchor FILE
    rate_limit FULL_PER_DAY KEY_MANAGEMENT_PER_DAY
    ip_rate_limit UPDATES_PER_MINUTE
    max_sig0_lifetime DURATION
    rollover_hold_down DURATION
    insecure_skip_chain_validation
}
~~~

* **ZONES** the scope in which zones may be onboarded, e.g. `.` for any zone. Which zones exist
  is decided by what has been onboarded, not by this list. If empty, the zones of the server block
  are used. A query for a name that isn't in an onboarded zone goes to the next plugin, or is
  answered REFUSED if there is none; an UPDATE for a zone outside the scope gets NOTAUTH.
* `db` stores zones, keys, versions and the audit trail in the bbolt database **PATH**, created
  if missing. A relative path is resolved below the *root* plugin's directory. Without it,
  everything is kept in memory and lost on restart or reload. Instances configured with the same
  database share their state, so a Corefile reload doesn't lose updates.
* `trust_anchor` replaces the built-in root trust anchors (KSK-2017, KSK-2024) with those in
  **FILE**: IANA's `root-anchors.xml` (RFC 7958) or DS/DNSKEY records for `.` in zone file format,
  e.g. the `root.key` that `unbound-anchor` maintains. Resolved below *root* when relative.
* `rate_limit` sets the per-zone quotas over a rolling 24 hours: **FULL_PER_DAY** content pushes
  and **KEY_MANAGEMENT_PER_DAY** control changes. Default `5 50`.
* `ip_rate_limit` sets the UPDATE attempts allowed per source address per minute, IPv6 counted
  per /64. Default `30`.
* `max_sig0_lifetime` is the longest SIG(0) validity window accepted. Default `1h5m`.
* `rollover_hold_down` is how long a KSK rollover not co-signed by the current KSK waits.
  Default `72h`; `0s` disables it.
* `insecure_skip_chain_validation` onboards any key without the chain-of-trust check. For local
  testing only.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metric is exported:

* `coredns_sazu_updates_total{server, rcode, status}` - UPDATE transactions by response code and
  SAZU status code (empty when there is none).

## Examples

Accept any zone, persist state, and let one secondary transfer the zones:

~~~ corefile
. {
    sazu . {
        db /var/lib/sazu/sazu.db
        trust_anchor /var/lib/unbound/root.key
    }
    transfer {
        to 192.0.2.53
    }
}
~~~

Accept pushes over DNS over HTTPS as well:

~~~ corefile
https://.:443 {
    tls cert.pem key.pem
    sazu . {
        db /var/lib/sazu/sazu.db
    }
}
~~~

A plain secondary for a SAZU zone is an ordinary *secondary* block:

~~~ corefile
example.org {
    secondary {
        transfer from 192.0.2.1:53
    }
}
~~~

## See Also

The SAZU specification in [github.com/mrwiora/sazu](https://github.com/mrwiora/sazu). RFC 2136
(dynamic update), RFC 2931 (SIG(0)), RFC 3007 (secure dynamic update), RFC 4035 and RFC 5155
(DNSSEC). The *file*, *transfer*, *secondary* and *any* plugins. In this directory:
[`docs/SAZU-GUIDE.md`](docs/SAZU-GUIDE.md), [`docs/SAZU-DEV.md`](docs/SAZU-DEV.md) (local sandbox),
[`docs/SAZU-THREAT-MODEL.md`](docs/SAZU-THREAT-MODEL.md),
[`docs/SAZU-DIFFUPDATES.md`](docs/SAZU-DIFFUPDATES.md) (why every push is a full zone),
[`docs/SAZU-CLUSTER.md`](docs/SAZU-CLUSTER.md) (several SAZU servers, not implemented) and
[`REGISTRARS.md`](REGISTRARS.md).

## Bugs

Every ZSK may push content for the whole zone; to give a signer part of the name space, delegate
that part as its own zone. Root trust anchors aren't tracked with RFC 5011; use a `trust_anchor`
file kept current by another tool. Only one SAZU server accepts updates for a zone; other servers
must be secondaries (`docs/SAZU-CLUSTER.md` specifies more). Minimal responses to ANY (RFC 8482)
are left to the *any* plugin, whose answer is unsigned.
