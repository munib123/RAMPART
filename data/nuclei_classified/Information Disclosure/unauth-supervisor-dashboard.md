# Nuclei Template: Unauth Supervisor Dashboard - Detect
**Template ID:** unauth-supervisor-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-supervisor-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Supervisor Dashboard was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

