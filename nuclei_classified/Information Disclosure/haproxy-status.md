# Nuclei Template: HAProxy Statistics Page - Detect
**Template ID:** haproxy-status
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`haproxy-status.yaml`)

## Vulnerability Information & PoC

## Description
HAProxy statistics page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/haproxy-status
GET {{BaseURL}}/haproxy?stats
```

## References
- https://www.exploit-db.com/ghdb/4191
