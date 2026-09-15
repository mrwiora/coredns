# SAZU local sandbox testing

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
a real domain to test live — see the README's "Setting up your zone"
section.
