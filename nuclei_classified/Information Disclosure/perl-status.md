# Nuclei Template: Apache Mod_perl Status Page - Detect
**Template ID:** perl-status
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`perl-status.yaml`)

## Vulnerability Information & PoC

## Description
Apache mod_perl status page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/perl-status
```

## References
- https://perl.apache.org/
