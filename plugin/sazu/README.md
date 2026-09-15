# sazu

## Name

*sazu* - implements SAZU (Self-Authenticated Zone Update): a customer's own
signer pushes DNSSEC-signed zone content to this server, authenticated purely
by SIG(0) (RFC 2931) riding on an RFC 2136 dynamic UPDATE, with no separate
account or API-key handshake. The server never holds a private key.

See the design document (`sazu-protocol.md` in
[github.com/mrwiora/sazu](https://github.com/mrwiora/sazu), the separate
repo this port was built against) for the full protocol; see this repo's
own `SAZU-PLAN.md` for exactly what of it this port implements today,
including chain-of-trust bootstrap, full and partial pushes, key
rollover, rate limiting, persistence, an audit trail, the §11
delegation-change watch daemon, and pushing over UDP, TCP, or HTTPS
(§7.3, raw wire bytes or a JSON envelope). Treat this as a working proof
of concept for testing the mechanism, not a production-ready deployment.

## Description

*sazu* accepts RFC 2136 dynamic UPDATE messages for the zones it's configured
for. A zone's first contact with this server is `sazuctl publish-trust`: it
generates a KSK and a ZSK together (or loads them if they already exist) and
presents both as a DNSKEY RRset — no zone content at all — signed with
SIG(0) using the KSK. Unless chain validation is disabled for local testing,
the KSK must match a DS record published for that zone by its real parent
zone (walked all the way from the DNS root). Once that succeeds, the KSK is
*pinned* and the ZSK is registered alongside it. From then on, every
routine content push (`sazuctl publish-zone`) is authenticated and signed
entirely by that ZSK, checked by cryptographic signature alone, with no
re-check against the parent chain on each push and no need to ever touch
the KSK again — unless it's deliberately rolled over.

*sazu* also answers ordinary queries for the zones it has onboarded, directly
from the content it has accepted.

## Syntax

```
sazu ZONES... {
    insecure_skip_chain_validation
    db PATH
    rate_limit FULL_PER_DAY KEY_MANAGEMENT_PER_DAY
    ip_rate_limit UPDATES_PER_MINUTE
}
```

* **ZONES** the *scope* this instance accepts SAZU pushes and queries
  for — not a fixed list of pre-declared domains. Use `.` to accept
  onboarding any domain at all, with no Corefile edit or server restart
  needed per new customer domain: which specific zones actually exist is
  entirely driven by what's been onboarded at runtime (in `Store`, and in
  the `db` file if configured), not by this list. Use a narrower zone
  (e.g. `customers.example.`) to restrict onboarding to subdomains
  delegated under one umbrella zone instead. If empty, the zones from the
  server block are used.
* `insecure_skip_chain_validation` disables the §10.2 chain-of-trust
  cross-check at first contact. **For local testing only** — see
  [Local sandbox testing](#local-sandbox-testing) below. Never set this in
  production: with it set, *any* self-signed key claiming *any* zone name is
  accepted on first contact, which is exactly the spoofable behavior the
  cross-check exists to prevent.
* `db PATH` persists every onboarded zone and pinned key to a SQLite
  database at PATH (created if it doesn't exist), so a restart doesn't
  forget them. **Omit this and everything is purely in-memory** — lost on
  every restart, which is fine for a quick one-off test but not for
  anything you want to survive a redeploy.
* `rate_limit FULL_PER_DAY KEY_MANAGEMENT_PER_DAY` overrides §12's per-zone
  push quotas, each enforced over a rolling 24h window: FULL_PER_DAY for a
  push that actually changes zone content (`publish-zone` — always a
  complete replacement; see "Considered approaches for differential
  updates" below for why there's no smaller alternative) and
  KEY_MANAGEMENT_PER_DAY for a push that only changes key state
  (`publish-trust`, `add-zsk`, `retire-zsk`, `rotate-key`), which costs
  this server far less to process, tracked independently.
  Defaults to `5 50` if omitted. An exceeded quota is refused with the
  `ERR_QUOTA_EXCEEDED` diagnostic. Not persisted across a restart.
* `ip_rate_limit UPDATES_PER_MINUTE` overrides §12's global, per-source-IP
  flood/scan throttle: a rolling 1-minute cap on UPDATE attempts from one
  address, independent of the per-zone quota above and of which zone
  name(s) it targets — closing the gap a per-zone-only quota leaves open
  against an attacker probing many different candidate zone names (each
  gets its own fresh, unused per-zone quota). Defaults to `30` if
  omitted. Checked before anything else in a push, including SIG(0)
  verification, since it bounds raw attempt volume, not just
  successfully authenticated attempts. An exceeded limit is refused with
  the `ERR_RATE_LIMITED` diagnostic. Not persisted across a restart.

  A first-contact or key-rollover attempt (the only operations expensive
  enough to be worth this) is additionally required to arrive over a
  connection-oriented transport — TCP, or HTTPS/HTTP3 — never plain UDP:
  a single forged UDP packet can claim any source address with nothing
  to disprove it, which would otherwise let an attacker bypass this
  quota entirely by spoofing a fresh address on every attempt. This
  never affects a real push in practice — a real signed push routinely
  exceeds a single UDP datagram's worth of content already (`sazuctl`
  already sends anything that large over TCP automatically, see
  `-target` above) — or an ordinary push to an already-pinned zone, which
  never triggers
  the chain-of-trust walk this protects. Refused with the
  `ERR_TRANSPORT_NOT_ALLOWED` diagnostic.

## Examples

Building the server and client, then onboarding a zone locally, verifying
it, pushing an updated full zone, and finally setting up a real zone with a
YAML zone definition against your registrar's chain of trust.

### Building the server

From the root of this checkout:

```
go generate coredns.go   # only needed if plugin.cfg has changed
go build -o coredns .
```

The `sazu` directive is already registered in `plugin.cfg`; a normal
`go build .` at the repo root produces a `coredns` binary with it included.

### The client: sazuctl

`plugin/sazu/cmd/sazuctl` is the customer-side tool — it never runs inside
CoreDNS, and in a real deployment runs on the customer's own infrastructure,
never the hoster's.

```
go build -o sazuctl ./plugin/sazu/cmd/sazuctl
```

Subcommands:

* `sazuctl init-zone -zone <zone> [-out <path>] [-format yaml|bind]` — write a
  starter zone definition for a brand-new domain, ready to extend. `-format`
  defaults to `yaml` (see **Creating a new zone**, below, for why); `bind`
  writes an ordinary, directly hand-editable zone file with the same starter
  content instead. Refuses to overwrite an existing file.
* `sazuctl zone-convert -in <path.yaml> -out <path.zone> [-zone <zone>]` —
  materialize a YAML zone definition as a real BIND-format zone file, for
  tracking both, or just inspecting what a YAML source actually expands to.
  `publish-zone` never needs this step itself — see below.
* `sazuctl keygen -out <path> [-zone <owner>] [-role ksk|zsk]` — generate a
  new Ed25519 key, saved in BIND9's private-key-file format. `-role`
  defaults to `ksk` — every zone needs exactly one, and this is what
  every version of this tool before the optional ZSK split always
  generated, so omitting it changes nothing.
* `sazuctl ds -zone <zone> -key <path>` — print the DS record for a key,
  ready to hand to a registrar. Generates the key first if it doesn't exist.
* `sazuctl publish-trust -zone <zone> -key <path> -zsk-key <path> [-target host:port|url] [-json]` —
  establish (or re-establish) a zone's KSK/ZSK trust relationship:
  generates a KSK and a ZSK together (created together, always — see
  **KSK, and the ZSK it's always paired with** below), or loads them if
  they already exist, and presents both as a DNSKEY RRset signed by the
  KSK. Carries **no zone content at all**. This is what onboards a zone
  (first contact); unless chain validation is disabled, the KSK must
  match a DS record at the real parent zone. Once this succeeds, the ZSK
  it registered is what every subsequent `publish-zone` push
  authenticates and signs with — the KSK isn't needed again unless it's
  rolled over (`sazuctl rotate-key -role ksk`).
* `sazuctl publish-zone -zone <zone> -zsk-key <path> -zonefile <path> [-previous-serial N] [-denial-of-existence nsec3|nsec] [-nsec3-iterations N] [-nsec3-salt HEX] [-nsec3-opt-out] [-target host:port|url] [-json]` —
  build, sign, and (optionally) send a zone's **complete, authoritative
  content**: every record in a BIND-format zone file. Authenticated and
  signed entirely by `-zsk-key` (registered first via `publish-trust`) —
  there is no `-key`/KSK flag on this command at all, and no DNSKEY of
  any kind rides along with it, since trust is already an established,
  separate fact by the time this runs. `-previous-serial` adds the
  SOA-serial staleness guard for a *re*-push; omit it (0) for a zone's
  first content push. `-zonefile` is required — either a BIND-format zone
  file, or a YAML zone definition (`.yaml`/`.yml`, converted
  automatically, no separate step); see `sazuctl init-zone` to create a
  starter one for a brand-new domain. `-denial-of-existence` picks the
  authenticated denial-of-existence proof and defaults to `nsec3` (RFC
  5155), additionally hiding the zone's name set from enumeration ("zone
  walking"); `-nsec3-iterations`/`-nsec3-salt` default to RFC 9276's
  current guidance (0, none) if omitted, and `-nsec3-opt-out` sets the
  Opt-Out flag. Pass `-denial-of-existence nsec` to fall back to plain
  RFC 4034 NSEC instead (the three NSEC3 flags above are ignored when you
  do). Either way this is a push-time choice the signer makes — the
  server just stores and serves whichever chain it was given. Every push
  is a fresh, full replacement of the zone's entire content — there is
  no partial/differential update command; see "Considered approaches for
  differential updates" below for why.
* `sazuctl push -zone <zone> -key <path> [-record name=ipv4] [-target host:port|url] [-json]` —
  the original minimal single-record demo, kept for quick protocol
  smoke-testing. It does **not** include a SOA, so it cannot by itself
  onboard a zone against this server (see `publish-trust`/`publish-zone`
  for that).
* `sazuctl contact -zone <zone> -key <path> [-address mailto:you@example.org]... [-clear] [-target host:port|url] [-json]` —
  register (or, with `-clear`, remove) the zone's §10.6 contact address(es):
  where `sazu-watchd`'s (§11) delegation-change alerts get sent.
  `-address` accepts `mailto:` for email or `http(s)://` for a webhook, and
  can repeat. This rides an ordinary authenticated push at a reserved owner
  name (`_sazu-contact.<zone>`) — it is never itself DNSSEC-signed or
  servable DNS content, just metadata carried alongside a real update.
* `sazuctl add-zsk -zone <zone> -ksk-key <path> -zsk-key <path> [-target host:port|url] [-json]` —
  register an additional ZSK on top of a zone's existing KSK: an
  ordinary push, authenticated by `-ksk-key`, that adds `-zsk-key`'s DNSKEY
  record. Generates `-zsk-key` if it doesn't exist yet. No chain-of-trust
  network walk and no registrar step. `publish-trust` already creates a
  zone's first ZSK automatically at onboarding — reach for this to add a
  second one, or to register a replacement after `retire-zsk`; see **KSK,
  and the ZSK it's always paired with** below for what this is for.
* `sazuctl retire-zsk -zone <zone> -ksk-key <path> -zsk-key <path> [-target host:port|url] [-json]` —
  the reverse: remove a previously registered ZSK. `-zsk-key` must already
  exist (never generated here).
* `sazuctl rotate-key -zone <zone> [-role ksk|zsk] ...` — the decision-support
  entry point for rotating *some* key when you're not sure which kind. Run
  with no `-role` at all, it makes no change and instead explains the
  ZSK-vs-KSK tradeoff (and, if you already have a ZSK, names its key tag) —
  see `sazuctl rotate-key -zone <zone> -current-zsk-key <path to your existing ZSK>`
  for a concrete example. Re-run with `-role zsk` (registers a new ZSK, then
  retires the old one — needs `-key`, `-current-zsk-key`, `-new-zsk-key`) or
  `-role ksk` (performs an ordinary §10.4 KSK rollover — needs `-key`,
  `-new-key` — printing a reminder that this always requires a new DS
  record at your registrar).

Every subcommand without `-target` just prints the signed wire bytes and
self-verifies — safe to run with nothing listening yet.

`-target` accepts either `host:port` (sent over TCP, always, by default —
it works regardless of message size or path MTU, at the cost of one extra
round trip; a `-udp` flag on the subcommands where a server can actually
accept it — never `push`, `publish-trust`, or `rotate-key -role ksk`, which are
always first-contact- or KSK-rollover-shaped and so always require a
connection-oriented transport — opts back into UDP, falling back to TCP
with a warning if the push is too large for one safe datagram) or an
`http://`/`https://` URL — §7.3's HTTPS carrier, POSTed to `<url>/dns-query` exactly like a DoH
client would, reusing the RFC 8484 convention as-is: no separate account or
authorization step, the same SIG(0)-signed push either way. `-json` sends a
small JSON envelope (`{"wire": "<base64>"}`) instead of a raw
`application/dns-message` body when pushing over HTTPS — the exact same
wire bytes either way, never a structural re-encoding of the message (see
`plugin/pkg/doh`'s own doc comments for why: SIG(0) signs literal wire
bytes, and a structural JSON translation has no lossless way back to
them). A Corefile only needs an `https://` (or `https3://`) server block
with a `sazu` directive in it to accept these — see **Syntax** above,
nothing carrier-specific to configure.

Every subcommand that reads or writes a key file (`keygen`'s `-out`, every
other subcommand's `-key`) also accepts `-key-passphrase-file <path>`
(§10.8): give it and that key file is encrypted at rest (scrypt + AES-256-
GCM) with the passphrase in the given file, instead of the plain
BIND-format file `sazuctl` writes by default. Omit it and nothing changes
from before this existed.

`plugin/sazu/cmd/sazu_stub_tld` is a minimal stand-in parent zone, useful for
manually checking DS-digest wire correctness offline. It **cannot** be used
to satisfy chain-of-trust validation itself, which always walks the real DNS
root — see the next two sections for how to actually test that.

#### Creating a new zone

`publish-zone` needs a zone file to push, and hand-writing a BIND-format one
from scratch means getting two things right that regularly trip people up:
the SOA serial number (an opaque integer with a conventional-but-unenforced
format) and the responsible-party mailbox (an email address written with
the `@` replaced by a `.`, and any literal `.` in the local part escaped).
`sazuctl init-zone` sidesteps both:

```
./sazuctl init-zone -zone yourdomain.example
```

writes `yourdomain.example.yaml` — a small, commented, directly editable
file:

```yaml
zone: yourdomain.example.
ttl: 3600
soa:
  ns: ns1.yourdomain.example.
  admin_email: hostmaster@yourdomain.example
  serial: auto   # today's date as YYYYMMDD00 -- see the file's own comment
  refresh: 3600
  retry: 900
  expire: 604800
  minttl: 3600
records:
  - name: www
    type: A
    value: 203.0.113.10
  - name: "@"
    type: MX
    value: "10 mail.yourdomain.example"
  - name: mail
    type: A
    value: 203.0.113.20
```

Add, edit, or remove entries under `records:` — a record's `value` is
ordinary zone-file syntax for whatever comes after the type (an MX's is
`"<priority> <target>"`, a TXT's is a quoted string, and so on), and a
`name` without a trailing dot is relative to the zone the same way a real
zone file already works, so this stays familiar to anyone who has written
one by hand. `publish-zone` accepts this file directly — no separate
conversion step. Establish trust once, then push it:

```
./sazuctl publish-trust -zone yourdomain.example -key client.private \
    -zsk-key zsk.private -target 127.0.0.1:15353
./sazuctl publish-zone -zone yourdomain.example -zsk-key zsk.private \
    -zonefile yourdomain.example.yaml -target 127.0.0.1:15353
```

`admin_email` and `serial: auto` are the two conveniences over a raw zone
file; everything else is the exact same content a zone file carries, just
in a shape that's easier to read a diff of. If you'd rather hand-edit a
real zone file directly, `init-zone -format bind` writes one with the same
starter content instead, or `sazuctl zone-convert -in <path.yaml> -out
<path.zone>` materializes one from a YAML source at any point (useful if
you want to track both, or just want to see exactly what a YAML file
expands to before pushing it).

### sazu-watchd: §11 delegation-change monitoring

`plugin/sazu/cmd/sazu_watchd` is a separate, standalone daemon -- never runs
inside CoreDNS -- that periodically runs two independent checks per
onboarded zone and alerts the zone's registered contact (`sazuctl contact`)
when either one's outcome changes:

* **Chain of trust** -- the same "does a DS matching this zone's pinned
  KSK exist at the parent" check first contact and a key rollover already
  perform. A pinned KSK's DS silently disappearing or changing at the
  registrar, without anyone re-pushing anything to this server, is exactly
  the kind of drift nothing else here would ever notice -- the registrar
  is outside this system entirely, so nothing short of asking it
  periodically can catch a change made there.
* **ZSK presence** -- for each zone with at least one registered ZSK, an
  ordinary DNS query confirms it's still actually present in what the zone
  is currently serving, compared against what this server's own database
  says should be registered. Unlike the chain-of-trust check, this isn't
  watching for drift at some external system (a ZSK is never registrar-
  anchored, never leaves this server's own database and served content;
  see keys.go's `KeyRole` doc comment) -- it's a low-cost canary against
  this server's own bugs or a corrupted database, not a routine concern.

Both checks share the same debounce discipline: a single failing/missing
pass doesn't alert on its own (two consecutive checks, 10 minutes apart at
the default interval, do), and a transient failure to even reach a zone's
own servers for the ZSK check is treated as inconclusive, never as
evidence the key was dropped.

```
go build -o sazu-watchd ./plugin/sazu/cmd/sazu_watchd
./sazu-watchd -db /path/to/the/same/sazu.db/CoreDNS/uses \
    -interval 5m \
    -smtp-addr smtp.example.org:587 -smtp-from alerts@example.org \
    -smtp-username alerts -smtp-password-file smtp-pass.txt
```

It reads the exact same SQLite file CoreDNS's `sazu` plugin writes to via
its `db` directive (both processes can safely have it open at once) --
there is no other configuration to keep in sync between the two. Alerts go
to whatever address(es) a zone registered with `sazuctl contact`: `mailto:`
addresses via SMTP (configure `-smtp-*` above, or leave them unset --
email alerts are simply skipped, with a logged error, until they're
configured), `https://`/`http://` addresses via a small JSON webhook POST.
A zone with no registered contact still gets every check logged, just
with nothing to notify externally.

Pass `-once` to run a single check pass and exit, instead of looping
forever -- useful for confirming the daemon can actually reach and parse
the database before wiring it into a real supervisor/systemd unit. Note
that `-once` resets its "last known good" state every time it starts (see
`watch.go`), so it never fires an alert on its own by design -- it exists
for connectivity/config verification, not as a substitute for the
long-running `-interval` loop a real deployment wants.

### Local sandbox testing

This is the fastest way to prove the whole mechanism works, using
`insecure_skip_chain_validation` since there's no real parent zone in a
sandbox to publish a DS record against.

1. **Start the server.** `sazu .` accepts onboarding *any* domain --
   nothing about which domain(s) you'll actually test needs deciding, or
   editing into the Corefile, up front:

   ```
   cat > Corefile <<'EOF'
   .:15353 {
       bind 127.0.0.1
       sazu . {
           insecure_skip_chain_validation
       }
       log
       errors
   }
   EOF
   ./coredns -conf Corefile
   ```

   (The steps below onboard `example.org` as a concrete example, but that
   name is chosen when you run `sazuctl`, not when you started the server
   above -- any other domain would work against this same, unmodified
   Corefile and running server.)

2. **Generate a KSK and establish trust** — `publish-trust` generates both
   the KSK and its paired ZSK together if they don't exist yet:

   ```
   ./sazuctl publish-trust -zone example.org -key client.private \
       -zsk-key zsk.private -target 127.0.0.1:15353
   ```

   A `Self-verification: OK` line followed by a NOERROR response means the
   KSK is pinned and the ZSK is registered — this zone carries no content
   yet.

3. **Write a small zone file and push its content**, authenticated and
   signed entirely by the ZSK (no `-previous-serial` for this first
   content push):

   ```
   cat > example.org.zone <<'EOF'
   $ORIGIN example.org.
   @   3600 IN SOA ns1.example.org. hostmaster.example.org. 2024010100 3600 900 604800 3600
   @   3600 IN NS  ns1.example.org.
   www 300  IN A   203.0.113.10
   EOF

   ./sazuctl publish-zone -zone example.org -zsk-key zsk.private \
       -zonefile example.org.zone -target 127.0.0.1:15353
   ```

   A `Self-verification: OK` line followed by a NOERROR response means the
   zone's content is now servable.

4. **Verify with dig** (or any DNS client — the server is a real,
   standards-compliant authoritative responder at this point):

   ```
   dig @127.0.0.1 -p 15353 www.example.org A
   dig @127.0.0.1 -p 15353 example.org SOA
   ```

5. **Edit the zone file and push it again**: add a record, then re-run
   `publish-zone` with the same ZSK — every push resends the zone's
   complete content, this new record included:

   ```
   cat >> example.org.zone <<'EOF'
   mail 300 IN A 203.0.113.20
   EOF

   ./sazuctl publish-zone -zone example.org -zsk-key zsk.private \
       -zonefile example.org.zone -target 127.0.0.1:15353

   dig @127.0.0.1 -p 15353 mail.example.org A
   ```

6. **Confirm impersonation is rejected**: generate a second, different key
   and try to push with it against the same zone as if it were the
   ZSK — it must be refused (`NOTAUTH`), and the record must not appear:

   ```
   ./sazuctl keygen -out attacker.private -zone example.org -role zsk

   cat >> example.org.zone <<'EOF'
   evil 300 IN A 198.51.100.1
   EOF

   ./sazuctl publish-zone -zone example.org -zsk-key attacker.private \
       -zonefile example.org.zone -target 127.0.0.1:15353

   dig @127.0.0.1 -p 15353 evil.example.org A   # should be NXDOMAIN
   ```

This exercises everything except the chain-of-trust walk itself (stubbed out
by `insecure_skip_chain_validation`). That part has its own dedicated,
network-based tests in `chain_test.go`/the package's other tests, and needs
a real domain to test live — see below.

### Setting up your zone

A dedicated, start-to-finish walkthrough for onboarding one real domain
against a real registrar: writing its YAML zone definition, generating its
KSK and ZSK independently (the real-world shape of key custody — see step
4), and pushing it. What's different from **Creating a new zone** above is
that a *real* domain also needs a real DS record at your registrar before
`publish-trust` will succeed, which this walks through end to end.

You do **not** need to change this domain's actual nameserver delegation,
and you do **not** need to run this server on a public IP or port 53 to do
any of this — the chain-of-trust check only asks "does the parent zone
publish a DS record matching this key," a normal, unauthenticated DNS
question anyone can ask against the real DNS root; it has nothing to do
with who currently serves the domain's real traffic. So you can point
`sazuctl` at a test instance of this server running anywhere reachable to
you, on any port, while your domain keeps working normally through its
real nameservers throughout.

1. **Start the server**, same as the sandbox walkthrough but with
   `insecure_skip_chain_validation` **removed** (this is the whole point of
   setting up against a real registrar). `sazu .` still means no domain
   name needs deciding or editing into the Corefile up front — including
   onboarding more than one real domain later, with no second server block
   or restart:

   ```
   cat > Corefile <<'EOF'
   .:15353 {
       bind 127.0.0.1
       sazu .
       log
       errors
   }
   EOF
   ./coredns -conf Corefile
   ```

   (A narrower scope, e.g. `sazu yourdomain.example`, works the same way if
   you'd rather this instance only ever accept that one domain — see
   **Syntax** above.)

   The server needs outbound UDP/53 reachability to the internet (real root
   and TLD servers) for the chain walk to succeed — the usual case for any
   machine with normal internet access, but worth checking explicitly if
   this runs somewhere with restrictive egress rules.

   It also needs **inbound TCP/53 reachable**, not just UDP/53: `sazuctl`
   sends anything over roughly 1.2 KB over TCP automatically (see
   `push.go`/`cmd/sazuctl`), since a real signed push routinely exceeds the
   path MTU and gets silently dropped as an IP fragment on UDP — found the
   hard way against a real security-group-restricted host. If
   `publish-trust` reports no response at all (not even a denial) against a
   server you otherwise know is up, check that inbound TCP/53 specifically
   isn't blocked, separately from UDP/53.

2. **Write the zone's YAML definition** with `sazuctl init-zone` — it
   sidesteps the two things that regularly trip people up when hand-writing
   a BIND-format zone file from scratch: the SOA serial number and the
   responsible-party mailbox's escaped-`@` syntax:

   ```
   ./sazuctl init-zone -zone yourdomain.example
   ```

   writes `yourdomain.example.yaml`, a small, commented, directly editable
   file:

   ```yaml
   zone: yourdomain.example.
   ttl: 3600
   soa:
     ns: ns1.yourdomain.example.
     admin_email: hostmaster@yourdomain.example
     serial: auto   # today's date as YYYYMMDD00 -- see the file's own comment
     refresh: 3600
     retry: 900
     expire: 604800
     minttl: 3600
   records:
     - name: www
       type: A
       value: 203.0.113.10
   ```

   Add, edit, or remove entries under `records:` to match your actual
   domain — a record's `value` is ordinary zone-file syntax for whatever
   comes after the type, and a `name` without a trailing dot is relative to
   the zone, same as a real zone file. `publish-zone` (step 7, below)
   accepts this file directly; there's no separate conversion step.

3. **If this domain is currently live with real traffic on it, read
   [Migrating an already-live domain](REGISTRARS.md#migrating-an-already-live-domain)
   in `REGISTRARS.md` before doing anything else in this section.**
   Publishing a DS record for a domain whose current host isn't also
   serving matching signatures breaks the *entire* domain — not just
   DNSSEC lookups — for every validating resolver, until that's fixed. A
   brand-new domain with no live traffic yet has none of this risk and can
   skip straight to the next step.

4. **Generate the zone's KSK and ZSK independently, each with its own
   `sazuctl keygen` command, then try establishing trust.** This is the
   real-world shape of key custody, not just a sandbox shortcut: the two
   keys never have to exist on the same machine at all.

   ```
   ./sazuctl keygen -out client.private -zone yourdomain.example -role ksk
   ./sazuctl keygen -out zsk.private -zone yourdomain.example -role zsk
   ```

   Run the first command only on whichever machine will keep the KSK
   long-term. The second can be run anywhere — including directly on the
   separate machine that should end up handling this zone's routine
   `publish-zone` pushes from now on, with `zsk.private` then copied (or
   generated in place) onto that machine and never onto the one holding
   the KSK. (`publish-trust`, below, also generates both keys itself if
   you skip this step and point it at paths that don't exist yet — a
   convenience for a quick sandbox test, but the explicit two-command
   form above is what a deployment with keys living on separate machines
   actually runs.)

   With both keys in hand, establish trust — this step carries no zone
   content, so the YAML file from step 2 isn't involved yet:

   ```
   ./sazuctl publish-trust -zone yourdomain.example -key client.private \
       -zsk-key zsk.private -target 127.0.0.1:15353
   ```

   The first attempt against a real, not-yet-onboarded domain is *expected*
   to be denied — that's the chain-of-trust cross-check working correctly,
   not a bug. `sazuctl` prints the exact DS record to give your registrar
   (plus the KSK's raw fields — type, algorithm, key tag, public key —
   for a registrar like AWS Route 53 that asks you to enter those by hand
   instead of pasting a DS record), and points you at `REGISTRARS.md` for
   registrar-specific steps.

   A different denial is also possible here: if a DS record already exists
   for this domain but doesn't match this key (`ERR_UNKNOWN_SIGNER`),
   `sazuctl` prints separate guidance for that instead — it usually means
   DNSSEC is already enabled for this domain under a different key
   (possibly its current host's own, if you followed step 3 above), not
   necessarily anything wrong with this key. Onboarding isn't blocked by
   this: `sazuctl` tells you to add this key's DS record *alongside* the
   existing one (most registrars accept more than one) rather than
   replacing it, so you can proceed the same way as this step without
   disturbing whatever's already keeping the domain validated.

   **As soon as this ZSK is registered (once trust succeeds, below), it
   is fully authorized for this zone** — not narrowly scoped to "push
   content." Whichever machine holds `zsk.private` can, from then on, do
   anything a SIG(0)-authenticated push can do here: push zone content,
   register or retire further ZSKs (for onboarding yet more signer
   machines — see `add-zsk`/`retire-zsk` above — without ever touching
   the KSK again), and manage the zone's contact address. There is no
   narrower per-key permission than that today; see README's **Known
   limitations**.

5. **Submit that DS record at your registrar** — every major registrar
   that supports DNSSEC has a form for this (look for "DS record,"
   "DNSSEC," or "delegation signer"); see `REGISTRARS.md` for what's
   documented so far per registrar. **This is the one genuinely manual,
   out-of-band step** — ordinary DNSSEC hygiene, not something SAZU
   replaces.

6. **Wait for it to propagate**, then confirm with `dig DS yourdomain.example
   +short` as the message above says, and **re-run the exact same
   `publish-trust` command from step 4.** Once the DS is visible, the same
   command that was denied now succeeds:

   ```
   Self-verification: OK (145 bytes)
   Sent 145 bytes to 127.0.0.1:15353
   Accepted (NOERROR).
   ```

   Trust is now established and the ZSK is registered — the zone itself
   still has no content yet.

7. **Push the zone's YAML content from step 2**, authenticated and signed
   entirely by the ZSK, and confirm the response is NOERROR, not REFUSED:

   ```
   ./sazuctl publish-zone -zone yourdomain.example -zsk-key zsk.private \
       -zonefile yourdomain.example.yaml -target 127.0.0.1:15353
   ```

   A REFUSED response here means the ZSK isn't the one `publish-trust`
   registered — recheck step 4/6; it has nothing to do with the DS/chain
   of trust any more, since that's a separate, already-settled fact by this
   point.

8. **Verify with dig**, then iterate by editing the YAML file and re-running
   `publish-zone` — every push resends the zone's complete content, so a
   newly added or edited record just needs to be in the file before the
   next push:

   ```
   dig @127.0.0.1 -p 15353 www.yourdomain.example A
   dig @127.0.0.1 -p 15353 yourdomain.example SOA
   ```

At no point in this flow does your domain's real, currently-serving
delegation change — this test server is never in the actual query path for
anyone but you, deliberately, so a mistake here can't take your domain
offline.

### Key rollover

A zone's KSK isn't permanent once pinned: `sazuctl rotate-key -role ksk`
generates a new one, prints its DS record for your registrar, and pushes
it for verification — the server checks the new key both signs this push
and has a matching DS at the parent (the identical check `publish-trust`
itself requires) before switching over:

```
./sazuctl rotate-key -zone yourdomain.example -role ksk \
    -key client.private -new-key new-client.private \
    -target 127.0.0.1:15353
```

Publish the new DS record at your registrar alongside the existing one
(most accept more than one, and both stay listed throughout — see
`REGISTRARS.md`) and wait for it to propagate; until the push above
succeeds, the old KSK keeps working normally. Once switched, remove the
old DS whenever you're ready — there's no rush, since a dangling extra DS
alongside the real one is safe. This always requires a new DS record and
always requires waiting for it to propagate, because the KSK is the one
and only key this server ever anchors to a parent DS. **The ZSK
`publish-trust` registered alongside the old KSK is untouched by this** —
it keeps authenticating and signing every `publish-zone` push exactly as
before, with no registrar step of its own.

### KSK, and the ZSK it's always paired with

Every zone has exactly one **KSK** (key-signing key) — the only key this
server ever anchors to a parent DS record, and the one `rotate-key -role
ksk` rotates. `sazuctl publish-trust` generates it together with a **ZSK**
(zone-signing key) at onboarding, always, and that pairing is the whole
point: the KSK proves the chain of trust once and is then set aside,
while the ZSK is what authenticates and signs every routine
`publish-zone` push from then on — an automation box running
`publish-zone` on a schedule never needs to hold the KSK at all. Rolling
the KSK over never invalidates an existing ZSK (see `KeyRegistry.PinKSK`),
so the two rotate completely independently.

Register an additional ZSK the same way `publish-trust` registered the
first one, authenticated by the KSK:

```
./sazuctl add-zsk -zone yourdomain.example -ksk-key client.private \
    -zsk-key second-zsk.private -target 127.0.0.1:15353
```

This is an ordinary push, authenticated by `-ksk-key` — **no
chain-of-trust network walk, no registrar interaction at all**, since a
ZSK is never DS-anchored; it's trusted purely because an already-trusted
key vouched for it. Retire a ZSK the same way, in reverse (`sazuctl
retire-zsk`) — useful after a suspected compromise, or just to replace
one on your own schedule with no registrar step whatsoever:

```
./sazuctl retire-zsk -zone yourdomain.example -ksk-key client.private \
    -zsk-key zsk.private -target 127.0.0.1:15353
```

Not sure which key you actually want to rotate? `sazuctl rotate-key
-zone yourdomain.example` (no `-role`) explains the tradeoff and tells
you exactly which flags to add for whichever you pick (`-role zsk`
registers a replacement and retires the old one in one command; `-role
ksk` performs the rollover above).

### Keys and validity: quick reference

Everything about what each key is for, how long anything actually stays
valid, and what's mandatory vs. configurable — in one place, so none of
it has to be pieced back together from the sections above.

| | **KSK** (key-signing key) | **ZSK** (zone-signing key) |
|---|---|---|
| **Use case** | Anchors the chain of trust: the only key ever matched against a DS record at your registrar. Authenticates `publish-trust` and a KSK rollover. | Routine, day-to-day key: authenticates and signs every `publish-zone` content push. An automation box running scheduled pushes only ever needs this one. |
| **Created** | `sazuctl publish-trust` — always generated together with its paired ZSK, never on its own. | Same `publish-trust` call, paired with the KSK from the start. |
| **Registrar interaction** | Required — a DS record at your registrar, every time this key changes (onboarding or rollover). | **Never** — a ZSK is trusted purely because an already-trusted key (the KSK) vouched for it; `add-zsk`/`retire-zsk`/`rotate-key -role zsk` involve no registrar step at all. |
| **How it expires** | It doesn't, on its own. Rotate deliberately with `rotate-key -role ksk` (best-practice hygiene, or a suspected compromise) — there is no forced cadence. | Same — doesn't expire on its own. Retire/replace on your own schedule (`retire-zsk` + `add-zsk`, or `rotate-key -role zsk` for both in one command). |
| **What invalidates it** | Nothing automatic. Rolling it over never invalidates any registered ZSK (`KeyRegistry.PinKSK`). | Nothing automatic. Rolling the KSK over never invalidates it either — the two rotate completely independently. |

**Signature validity windows** (the one place an actual clock matters):

| Signature | Covers | Validity | What happens if you let it lapse |
|---|---|---|---|
| RRSIG (zone content) | Every record in a `publish-zone` push — this is the one that determines whether your zone validates for real DNSSEC resolvers. | **30 days** (`DefaultSignatureValidity`), fixed regardless of which key signs it — using the KSK instead of the ZSK does not extend it. | Resolvers see an expired signature once their cache re-fetches past it — SERVFAIL for a validating resolver. **You must run `publish-zone` again at least this often**, even with zero content changes, purely to refresh signatures. |
| SIG(0) (transaction) | The UPDATE message itself, for the ~1 hour around when `sazuctl` sends it. | ~1 hour, set fresh by `sazuctl` on every push. | Nothing to manage — this isn't a stored credential, just replay protection for one in-flight push. Never confuse this with the RRSIG window above; they protect different things on completely different timescales. |

**What's mandatory vs. configurable:**

- **Content-signature verification is mandatory, unconditionally, with no way to turn it off.** Every pushed RRset must carry a covering RRSIG that actually verifies, or the push is rejected (`NOTAUTH` / `ERR_SIG_INVALID`) before anything is applied. There is no "trust SIG(0) alone" mode — SIG(0) proves who sent a push, never that the content itself would validate for a real resolver.
- **`insecure_skip_chain_validation`** is the one remaining opt-in toggle anywhere in this plugin, and it's exactly what its name says: disables the §10.2 DS cross-check at first contact, for local testing only where there's no real parent zone to check against. **Never set this in production** — see [Syntax](#syntax) above. Nothing else in this plugin is optional in a way that weakens what gets verified.

## Considered approaches for differential updates

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

## Known limitations

Worth being explicit about what this proof of concept does *not* cover, so
a real-world test isn't mistaken for a production trial run:

* **In-memory only if `db` is omitted.** Persistence via `db PATH` (SQLite)
  is available and tested; without it, restarting the server loses every
  onboarded zone and pinned key.
* **Onboarding is two round trips, not one.** `publish-trust` establishes
  the KSK/ZSK trust relationship and `publish-zone` pushes content
  separately — a zone is briefly "trusted but empty" in between, unable
  to answer anything but NXDOMAIN. This is a deliberate consequence of
  keeping trust establishment and content genuinely separate (see
  keys.go's `KeyRole` doc comment); it's never a problem in practice
  since nothing serves traffic in that window anyway.
* **No per-key authorization scoping.** Independent per-instance pusher
  identities for HA/multi-signer deployments already work today: a zone
  can register more than one ZSK (`add-zsk`/`retire-zsk`), each held by
  a different signer machine, each independently revocable, and the
  audit trail (`AuditEntry.KeyTag`/`KeyRole`) records which one
  authenticated every transaction — "which signer pushed this" is
  answerable after the fact. What's still genuinely unaddressed: every
  registered key (KSK or ZSK alike) is authorized to do everything a
  SIG(0)-authenticated push can do here — push zone content, register or
  retire another ZSK, manage the contact address — with no way to scope
  a specific key to a narrower set of operations. See SAZU-PLAN.md's
  KSK/ZSK section for why that's a materially different problem
  (authorization, not a DNSSEC key role) from the KSK/ZSK split itself.
