# Nuclei Template: X Prober Server - Information Disclosure
**Template ID:** xprober-service
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`xprober-service.yaml`)

## Vulnerability Information & PoC

## Description
X Prober Server information disclosure was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/xprober.php
```

## References
- https://github.com/kmvan/x-prober
- https://twitter.com/bugbounty_tips/status/1339984643517423616
