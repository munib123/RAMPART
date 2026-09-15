# Nuclei Template: Perforce Server - Unauthenticated Remote Depot Access
**Template ID:** perforce-remote-depot-unauth
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`perforce-remote-depot-unauth.yaml`)

## Vulnerability Information & PoC

## Description
Detected Perforce server allowed unauthenticated remote depot access via the hidden built-in "remote" user. This affected server versions below 2025.1 when the security level was below 4 (default is 0). The depot file listing and change list numbers were retrieved without authentication using the rmt-DbPipe RPC against the db.rev table.

## References
- https://morganrobertson.net/p4wned/
- https://www.keysight.com/blogs/en/tech/nwvs/2022/06/08/a-sneak-peek-into-the-protocol-behind-perforce
- https://help.perforce.com/helix-core/release-notes/current/relnotes.txt
