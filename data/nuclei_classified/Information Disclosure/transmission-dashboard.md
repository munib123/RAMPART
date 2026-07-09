# Nuclei Template: Transmission Dashboard - Detect
**Template ID:** transmission-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`transmission-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Transmission dashboard was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/transmission/web/
```

## References
- https://transmissionbt.com/
