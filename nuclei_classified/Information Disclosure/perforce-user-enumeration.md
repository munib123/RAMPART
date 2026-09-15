# Nuclei Template: Perforce Server - User Enumeration
**Template ID:** perforce-user-enumeration
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`perforce-user-enum.yaml`)

## Vulnerability Information & PoC

## Description
Detected Perforce server allowed anonymous user listing due to run.users.authorize being set to 0 (the default). The server returned a full list of users including usernames, email addresses, and full names without authentication. Both ASCII and Unicode server modes were affected. SSL-enforcing servers are not affected.

## References
- https://morganrobertson.net/p4wned/
- https://www.keysight.com/blogs/en/tech/nwvs/2022/06/08/a-sneak-peek-into-the-protocol-behind-perforce
- https://help.perforce.com/helix-core/release-notes/current/relnotes.txt
