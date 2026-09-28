# SAZU guide

How to build and run the `sazu` plugin, onboard and maintain zones with
`sazuctl`, and monitor them with `sazu-watchd`. The plugin's reference is
[`README.md`](../README.md); the protocol is specified in `readme.md` of
[github.com/mrwiora/sazu](https://github.com/mrwiora/sazu).

## Keys and validity: quick reference

Everything about what each key is for, how long anything actually stays
valid, and what's mandatory vs. configurable — in one place, so none of
it has to be pieced back together from the sections above.

| | **KSK** (key-signing key) | **ZSK** (zone-signing key) |
|---|---|---|
| **Use case** | Anchors the chain of trust: the only key ever matched against a DS record at your registrar. Authenticates `publish-trust`, a KSK rollover, and every other change to the zone's key set or contact (`add-zsk`, `retire-zsk`, `contact`, `decommission-zone`), and is the only key allowed to sign the DNSKEY RRset. | Routine, day-to-day key: authenticates and signs every `publish-zone` content push -- and nothing else. An automation box running scheduled pushes only ever needs this one, and a stolen ZSK can't register keys, retire keys, or redirect alerts. |
| **Created** | `sazuctl publish-trust` — always generated together with its paired ZSK, never on its own. | Same `publish-trust` call, paired with the KSK from the start. |
| **Registrar interaction** | Required — a DS record at your registrar, every time this key changes (onboarding or rollover). | **Never** — a ZSK is trusted purely because an already-trusted key (the KSK) vouched for it; `add-zsk`/`retire-zsk`/`rotate-key -role zsk` involve no registrar step at all. |
| **How it expires** | It doesn't, on its own. Rotate deliberately with `rotate-key -role ksk` (best-practice hygiene, or a suspected compromise) — there is no forced cadence. | Same — doesn't expire on its own. Retire/replace on your own schedule (`retire-zsk` + `add-zsk`, or `rotate-key -role zsk` for both in one command). |
| **What invalidates it** | Nothing automatic. Rolling it over never invalidates any registered ZSK (`KeyRegistry.PinKSK`). | Nothing automatic. Rolling the KSK over never invalidates it either — the two rotate completely independently. |

**Signature validity windows** (the one place an actual clock matters):

| Signature | Covers | Validity | What happens if you let it lapse |
|---|---|---|---|
| RRSIG (zone content) | Every record in a `publish-zone` push — this is the one that determines whether your zone validates for real DNSSEC resolvers. | **30 days** (`DefaultSignatureValidity`), fixed regardless of which key signs it — using the KSK instead of the ZSK does not extend it. | Resolvers see an expired signature once their cache re-fetches past it — SERVFAIL for a validating resolver. **You must run `publish-zone` again at least this often**, even with zero content changes, purely to refresh signatures. |
| SIG(0) (transaction) | The UPDATE message itself, for the ~1 hour around when `sazuctl` sends it. | ~1 hour, set fresh by `sazuctl` on every push; the server refuses anything longer than `max_sig0_lifetime` (default 1h5m). | Nothing to manage — this isn't a stored credential. A captured push still can't be applied twice or behind a newer one: content pushes must raise the SOA serial, and control changes must name the zone's current version (see [Replay protection](#replay-protection)). Never confuse this with the RRSIG window above; they protect different things on completely different timescales. |

**What's mandatory vs. configurable:**

- **Content-signature verification is mandatory, unconditionally, with no way to turn it off.** Every pushed RRset must carry a covering RRSIG that actually verifies, or the push is rejected (`REFUSED` / `ERR_SIG_INVALID`) before anything is applied. There is no "trust SIG(0) alone" mode — SIG(0) proves who sent a push, never that the content itself would validate for a real resolver.
- **`insecure_skip_chain_validation`** is the one opt-in toggle in this plugin, and it's exactly what its name says: disables the §7.2 DS cross-check at first contact, for local testing only where there's no real parent zone to check against. **Never set this in production** — see the plugin README's *Syntax*. Nothing else in this plugin is optional in a way that weakens what gets verified.

## Setting up your zone

A dedicated, start-to-finish walkthrough for onboarding one real domain
against a real registrar: writing its YAML zone definition, generating its
KSK and ZSK independently (the real-world shape of key custody — see step
4), and pushing it. What's different from **Creating a new zone** below is
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
   the plugin README's *Syntax*.)

   The server needs outbound UDP/53 reachability to the internet (real root
   and TLD servers) for the chain walk to succeed — the usual case for any
   machine with normal internet access, but worth checking explicitly if
   this runs somewhere with restrictive egress rules.

   It also needs **inbound TCP/53 reachable**, not just UDP/53: `sazuctl`
   sends pushes over TCP by default, since a signed push routinely exceeds
   the path MTU and IP fragments are often dropped. If `publish-trust`
   reports no response at all (not even a denial) against a server you
   know is up, check that inbound TCP/53 isn't blocked.

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
   [Migrating an already-live domain](../REGISTRARS.md#migrating-an-already-live-domain)
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
   not a bug. Onboarding only ever succeeds once your registrar is already
   publishing a matching DS record; until then, this server saves nothing
   at all — no zone, no pinned KSK, no registered ZSK — so a denied attempt
   is exactly as safe to retry as the first one, as many times as it takes.
   `sazuctl` prints the exact DS record to give your registrar (plus the
   KSK's raw fields — type, algorithm, key tag, public key — for a
   registrar like AWS Route 53 that asks you to enter those by hand instead
   of pasting a DS record), and points you at `REGISTRARS.md` for
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

   **Once this ZSK is registered (once trust succeeds, below), it can
   push zone content — and only that.** Registering or retiring ZSKs,
   changing the contact address, and decommissioning the zone all need
   the KSK: they change the zone's key set or where its alerts go, and
   the DNSKEY RRset must be signed by the KSK anyway for validating
   resolvers to accept it. So whichever machine holds `zsk.private` can
   publish content, but a stolen ZSK can be retired with one KSK-signed
   `retire-zsk` and can't lock you out first.

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
   next push. The server only accepts a push whose SOA serial is newer
   than the one it serves; if yours isn't (an edited file with the same
   serial, or `serial: auto` pushed twice on one day), `publish-zone`
   publishes it with the served serial + 1 and says so:

   ```
   dig @127.0.0.1 -p 15353 www.yourdomain.example A
   dig @127.0.0.1 -p 15353 yourdomain.example SOA
   ```

At no point in this flow does your domain's real, currently-serving
delegation change — this test server is never in the actual query path for
anyone but you, deliberately, so a mistake here can't take your domain
offline.

## Building the server

From the root of this checkout:

```
go generate coredns.go   # only needed if plugin.cfg has changed
go build -o coredns .
```

The `sazu` directive is already registered in `plugin.cfg`; a normal
`go build .` at the repo root produces a `coredns` binary with it included.

## The client: sazuctl

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
  defaults to `ksk`.
* `sazuctl ds -zone <zone> -key <path>` — print the DS record for a key,
  ready to hand to a registrar. Generates the key first if it doesn't exist.
* `sazuctl publish-trust -zone <zone> -key <path> -zsk-key <path> [-target host:port|url]` —
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
* `sazuctl publish-zone -zone <zone> -zsk-key <path> -zonefile <path> [-previous-serial N] [-keep-serial] [-denial-of-existence nsec3|nsec] [-nsec3-iterations N] [-nsec3-salt HEX] [-nsec3-opt-out] [-target host:port|url]` —
  build, sign, and (optionally) send a zone's **complete, authoritative
  content**: every record in a BIND-format zone file. Authenticated and
  signed entirely by `-zsk-key` (registered first via `publish-trust`) —
  there is no `-key`/KSK flag on this command at all, and no DNSKEY of
  any kind rides along with it, since trust is already an established,
  separate fact by the time this runs. `-previous-serial` adds the
  SOA-serial staleness guard for a *re*-push; omit it (0) for a zone's
  first content push. With `-target`, the zone file's SOA serial is
  raised to the served serial + 1 if it isn't already newer (the server
  refuses a push that doesn't move the serial forward); `-keep-serial`
  sends it unchanged instead. `-zonefile` is required — either a BIND-format zone
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
  no partial/differential update command; see
  [`SAZU-DIFFUPDATES.md`](SAZU-DIFFUPDATES.md) for why.
* `sazuctl contact -zone <zone> -key <path> [-address mailto:you@example.org]... [-clear] [-target host:port|url]` —
  register (or, with `-clear`, remove) the zone's §11.4 contact address(es):
  where `sazu-watchd`'s alerts get sent. `-key` must be the zone's
  KSK — the server refuses a contact change authenticated by a ZSK.
  `-address` accepts `mailto:` for email or `https://` for a webhook, and
  can repeat. This rides an ordinary authenticated push at a reserved owner
  name (`_sazu-contact.<zone>`) — it is never itself DNSSEC-signed or
  servable DNS content, just metadata carried alongside a real update.
* `sazuctl add-zsk -zone <zone> -ksk-key <path> -zsk-key <path> -target host:port|url` —
  register an additional ZSK on top of a zone's existing KSK: an
  ordinary push, authenticated by `-ksk-key` (which must be the zone's
  KSK), that adds `-zsk-key`'s DNSKEY record. Generates `-zsk-key` if it doesn't exist yet. No chain-of-trust
  network walk and no registrar step. `publish-trust` already creates a
  zone's first ZSK automatically at onboarding — reach for this to add a
  second one, or to register a replacement after `retire-zsk`; see **KSK,
  and the ZSK it's always paired with** below for what this is for. Unlike
  every other subcommand, `-target` is **required**, not optional: an
  RRSIG covers a whole RRset, so correctly re-signing the DNSKEY set this
  adds a record to means first querying `-target` live for its current,
  complete membership — this tool holds no server-side state of its own
  to fall back on.
* `sazuctl retire-zsk -zone <zone> -ksk-key <path> -zsk-key <path> -target host:port|url` —
  the reverse: remove a previously registered ZSK. `-zsk-key` must already
  exist (never generated here). `-target` is required for the same reason
  as `add-zsk`.
* `sazuctl rotate-key -zone <zone> [-role ksk|zsk] ...` — the decision-support
  entry point for rotating *some* key when you're not sure which kind. Run
  with no `-role` at all, it makes no change and instead explains the
  ZSK-vs-KSK tradeoff (and, if you already have a ZSK, names its key tag) —
  see `sazuctl rotate-key -zone <zone> -current-zsk-key <path to your existing ZSK>`
  for a concrete example. Re-run with `-role zsk` (registers a new ZSK, then
  retires the old one — needs `-key`, `-current-zsk-key`, `-new-zsk-key`) or
  `-role ksk` (performs an ordinary §8.2 KSK rollover — needs `-key`,
  `-new-key` — printing a reminder that this always requires a new DS
  record at your registrar). `-target` is required for either role, for
  the same reason as `add-zsk`/`retire-zsk` above (a rollover re-signs the
  complete resulting DNSKEY set too, not just the new KSK).
* `sazuctl decommission-zone -zone <zone> -ksk-key <path> -yes [-target host:port|url]` —
  permanently removes a zone: its KSK, every registered ZSK, all content
  and its NSEC/NSEC3 chain, and its contact registration, from the
  server (and its `db`, if configured) — there is otherwise no way to
  fully un-onboard a zone at all; every ordinary RFC 2136 delete-shaped
  op deliberately protects the apex SOA. Authenticated by `-ksk-key`
  specifically, which must already exist (never generated here — a
  freshly generated key could never match what the server has pinned,
  guaranteeing failure). `-yes` is a required, explicit confirmation:
  without it, the command refuses to build or send anything at all. This
  says nothing about the parent DS record — removing that at your
  registrar, if you want to, stays your own out-of-band step, same as
  publishing one always has been. The exact same zone name can be
  onboarded again afterward with `publish-trust`, from scratch, with
  nothing left over to conflict with it.

Every control change — `publish-trust`, `add-zsk`, `retire-zsk`,
`rotate-key`, `contact`, `decommission-zone`, and a zone's first
`publish-zone` — carries the zone's current version (see
[Replay protection](#replay-protection)), read from `-target`. Where a
command can sign without `-target`, pass `-zone-version N` instead
(`dig TXT _sazu-version.<zone>` shows it); `publish-trust` for a zone
the server has never seen defaults to `0`.

Every subcommand *other than* `add-zsk`, `retire-zsk`, and `rotate-key`
run without `-target` just prints the signed wire bytes and self-verifies
— safe to run with nothing listening yet.

`-target` accepts either `host:port` — sent over TCP by default, which
works whatever the message size or path MTU; `-udp`, on the subcommands
where the server accepts UDP (not `publish-trust` or `rotate-key -role
ksk`, which need a connection-oriented transport), uses UDP when the push
fits in one 512-byte datagram and TCP otherwise — or an `https://` URL,
for DNS over HTTPS (RFC 8484): the push is POSTed to `<url>/dns-query` as
`application/dns-message`, the same SIG(0)-signed bytes either way. A
Corefile only needs an `https://` (or `https3://`) server block with a
`sazu` directive to accept these — see the plugin README's *Syntax*.

Every subcommand that reads or writes a key file (`keygen`'s `-out`, every
other subcommand's `-key`) also accepts `-key-passphrase-file <path>`
(§11.6): give it and that key file is encrypted at rest (scrypt + AES-256-
GCM) with the passphrase in the given file, instead of the plain
BIND-format file `sazuctl` writes by default.

`plugin/sazu/cmd/sazu_stub_tld` is a minimal stand-in parent zone, useful for
manually checking DS-digest wire correctness offline. It **cannot** be used
to satisfy chain-of-trust validation itself, which always walks the real DNS
root — see the next two sections for how to actually test that.

### Creating a new zone

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

## sazu-watchd: delegation-change monitoring (§11.4)

`plugin/sazu/cmd/sazu_watchd` is a separate, standalone daemon -- never runs
inside CoreDNS -- that periodically runs four independent checks per
onboarded zone and alerts the zone's registered contact (`sazuctl contact`)
when any of them needs attention:

* **Chain of trust** -- the same "does a DS matching this zone's pinned
  KSK exist at the parent" check first contact and a key rollover already
  perform. A pinned KSK's DS silently disappearing or changing at the
  registrar, without anyone re-pushing anything to this server, is exactly
  the kind of drift nothing else here would ever notice -- the registrar
  is outside this system entirely, so nothing short of asking it
  periodically can catch a change made there.
* **Pending KSK rollover** -- a rollover that wasn't co-signed by the
  zone's current KSK (see [Key rollover](#key-rollover)) alerts the
  contact at once, first pass included: if the owner didn't start it,
  the hold-down is their time to run `sazuctl cancel-rollover`. A
  recovery follows once it completes or is cancelled.
* **Signature expiry** -- this server never re-signs anything, so a zone
  whose owner's automation stops pushing goes bogus for validating
  resolvers the moment its earliest RRSIG expires, with no symptom on
  the server itself. The daemon warns the zone's contact once that
  expiration is within `-expiry-warning` (default 7 days) -- right away,
  even on its first pass -- and sends a recovery once a fresh push
  moves it out again.
* **ZSK presence** -- for each zone with at least one registered ZSK, an
  ordinary DNS query confirms it's still actually present in what the zone
  is currently serving, compared against what this server's own database
  says should be registered. Unlike the chain-of-trust check, this isn't
  watching for drift at some external system (a ZSK is never registrar-
  anchored, never leaves this server's own database and served content;
  see keys.go's `KeyRole` doc comment) -- it's a low-cost canary against
  this server's own bugs or a corrupted database, not a routine concern.

The chain-of-trust and ZSK checks share the same debounce discipline: a single failing/missing
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

It reads the same database file CoreDNS's `sazu` plugin writes to via its
`db` directive. Neither process keeps the file open between operations,
so they take turns on its lock; there is no other configuration to keep in
sync between the two. Alerts go
to whatever address(es) a zone registered with `sazuctl contact`: `mailto:`
addresses via SMTP (configure `-smtp-*` above, or leave them unset --
email alerts are simply skipped, with a logged error, until they're
configured), `https://` addresses via a small JSON webhook POST.
A zone with no registered contact still gets every check logged, just
with nothing to notify externally.

Webhook addresses are chosen by zone owners, not by you, so the daemon
only delivers webhooks to public addresses: a connection to a loopback,
private, link-local or CGNAT address is refused (checked on the address
actually connected to, after DNS resolution), redirects are not
followed, and no HTTP proxy from the environment is used.
`-webhook-allow-private` lifts this, for deployments where every zone
owner is trusted.

`-trust-anchor FILE` takes the same root trust anchor file as the
plugin's `trust_anchor` directive; keep the two pointed at the same,
maintained file.

Pass `-once` to run a single check pass and exit, instead of looping
forever -- useful for confirming the daemon can actually reach and parse
the database before wiring it into a real supervisor/systemd unit. Note
that `-once` resets its "last known good" state every time it starts (see
`watch.go`), so it never fires an alert on its own by design -- it exists
for connectivity/config verification, not as a substitute for the
long-running `-interval` loop a real deployment wants.

## Local sandbox testing

The fastest way to prove the whole mechanism works, using
`insecure_skip_chain_validation` since there's no real parent zone in a
sandbox to publish a DS record against — start the server, establish
trust, push and re-push a zone, and confirm an impersonation attempt is
rejected, all against `127.0.0.1`. See
[`SAZU-DEV.md`](SAZU-DEV.md) for the full walkthrough.

## Key rollover

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
`REGISTRARS.md`) and wait for it to propagate, then at least the parent's
DS TTL more so resolvers that cached the old DS set have refreshed it;
until the push above succeeds, the old KSK keeps working normally.

`rotate-key -role ksk` also signs the new DNSKEY set with the *old*
KSK. That co-signature proves the current key holder agrees, and lets
the server apply the rollover at once. Without it — the old KSK is lost,
`-lost-old-key` — a rollover is proven only by the new key and its DS,
which is exactly what someone who took over your registrar account could
produce. So the server then only records it as **pending**
(`ERR_ROLLOVER_PENDING`, with the earliest completion time),
`sazu-watchd` alerts the zone's contact, and it completes only when the
same command is run again after the hold-down (default 72 hours) with
the DS still published. Any change the current KSK makes in the
meantime cancels it — explicitly:

```
./sazuctl cancel-rollover -zone yourdomain.example -ksk-key client.private \
    -target 127.0.0.1:15353
```

**Once switched, remove the old DS promptly** — as soon as the old
DNSKEY RRset has had time to expire from caches (its TTL). For
resolvers a dangling extra DS is harmless, but for this server it is
not: a KSK rollover only needs a key that signs its own push and
matches *some* DS at the parent, so as long as the old DS is published,
anyone holding the old KSK can roll the zone straight back to it. That
matters most exactly when you're rotating because the old key may have
leaked. This always requires a new DS record and
always requires waiting for it to propagate, because the KSK is the one
and only key this server ever anchors to a parent DS. **The ZSK
`publish-trust` registered alongside the old KSK is untouched by this** —
it keeps authenticating and signing every `publish-zone` push exactly as
before, with no registrar step of its own.

## KSK, and the ZSK it's always paired with

Every zone has exactly one **KSK** (key-signing key) — the only key this
server ever anchors to a parent DS record, the only key allowed to sign
the zone's DNSKEY RRset or change its key set or contact, and the one
`rotate-key -role ksk` rotates. `sazuctl publish-trust` generates it together with a **ZSK**
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

## Status codes

Every refusal carries a SAZU status code (e.g. `ERR_NO_DS_PUBLISHED`,
specification §10) as an RFC 8914 Extended DNS Error when the request
carries EDNS(0) — `sazuctl` always sends it. The EXTRA-TEXT is the code,
followed by `: ` and a detail where there is one (the failing RRset, a
pending rollover's earliest completion time); INFO-CODE is 18
(Prohibited) for policy refusals, 1/2 for a weak key algorithm or DS
digest, 6 (DNSSEC Bogus) for a signature that doesn't verify, 7
(Signature Expired), and 0 otherwise. RCODEs follow RFC 2136 and RFC
3007: FORMERR and NOTZONE for a malformed update (RFC 2136 §3.2.1,
§3.4.1.3), NXRRSET for a stale version prerequisite, REFUSED for
anything unauthorized or refused by policy.

## Replay protection

A signed UPDATE stays cryptographically valid until its SIG(0) expires.
What keeps a captured one from ever being applied again are two
per-zone counters that are part of the zone's own state — no clocks, no
per-message history:

* **Content pushes** must raise the SOA serial (RFC 1982); otherwise
  `ERR_STALE_SERIAL`. An older push, replayed or held back and delivered
  late, can never land over a newer one.
* **Control changes** — onboarding, a KSK rollover, `add-zsk`/`retire-zsk`,
  `contact`, `decommission-zone` — must carry the zone's current
  **version** as an RFC 2136 prerequisite (a TXT record at
  `_sazu-version.<zone>` in the prerequisite section), and each accepted
  one increments it. A message names exactly one version, so it applies
  at most once, and two changes signed for the same version can't both
  apply. Missing: `ERR_VERSION_REQUIRED`; not current: `NXRRSET` with
  `ERR_STALE_VERSION` (re-read and re-sign). A zone's first content push
  has no serial yet, so it needs the version too.

The server publishes the version (unsigned) as `TXT _sazu-version.<zone>`
— `0` for a zone it has never seen — and `sazuctl` reads it from
`-target` automatically. To sign a control change offline (e.g. on the
KSK's air-gapped host), pass `-zone-version N` instead. Routine content
pushes never change the version, so a change prepared offline stays
valid across them. The version is persisted with the update that
changes it and survives decommission (which increments it), so neither
a restart nor a re-onboarding lets an old message apply. It is one
number per zone, so any future replica of a zone can carry it along
with the zone itself.

Independently, a SIG(0) valid for longer than `max_sig0_lifetime` is
refused.
