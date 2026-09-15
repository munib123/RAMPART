# Nuclei Template: Perforce Server - Passwordless User Accounts
**Template ID:** perforce-passwordless-users
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** Critical
**CWE:** CWE-306
**Source:** Nuclei Template (`perforce-passwordless-users.yaml`)

## Vulnerability Information & PoC

## Description
Perforce server contained user accounts with no password set, allowing unauthenticated access as those users. The user-users RPC was issued with the tag parameter to switch the server to tagged (client-FstatInfo) output, which omits the Password field entirely for passwordless accounts. Both ASCII and Unicode server modes were affected. SSL-enforcing servers are not affected.

## References
- https://morganrobertson.net/p4wned/
- https://www.keysight.com/blogs/en/tech/nwvs/2022/06/08/a-sneak-peek-into-the-protocol-behind-perforce
- https://help.perforce.com/helix-core/release-notes/current/relnotes.txt
