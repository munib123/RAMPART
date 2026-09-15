# Nuclei Template: Webalizer Log Analyzer Configuration - Detect
**Template ID:** plesk-stat
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`plesk-stat.yaml`)

## Vulnerability Information & PoC

## Description
Webalizer log analyzer configuration was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/plesk-stat/
```

## References
- https://webalizer.net/
