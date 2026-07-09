# Nuclei Template: RethinkDB Administration Console - Detect
**Template ID:** rethinkdb-admin-console
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`rethinkdb-admin-console.yaml`)

## Vulnerability Information & PoC

## Description
RethinkDB Administration Console was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/#dashboard
```

## References
- https://rethinkdb.com/
