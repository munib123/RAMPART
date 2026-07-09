# Nuclei Template: Perforce Server - Information Disclosure
**Template ID:** perforce-info-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`perforce-info-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Perforce server exposed internal server information without authentication due to dm.info.hide being set to 0 (the default). Disclosed fields included the server version, server root path, internal server address, and license information. SSL-enforcing servers are not affected.

## References
- https://morganrobertson.net/p4wned/
- https://www.keysight.com/blogs/en/tech/nwvs/2022/06/08/a-sneak-peek-into-the-protocol-behind-perforce
- https://help.perforce.com/helix-core/release-notes/current/relnotes.txt
