# Nuclei Template: DEOS OPENview Admin Panel Unauthenticated Access
**Template ID:** deos-openview-panel
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`deos-openview-admin.yaml`)

## Vulnerability Information & PoC

## Description
The DEOS OPENview administrative panel is accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/client/index.html
```

## References
- https://www.deos-ag.com/
