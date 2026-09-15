# Nuclei Template: DEOS OPEN 500EMS Controller - Admin Exposure
**Template ID:** deos-open500ems-panel
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** High
**CWE:** CWE-284
**Source:** Nuclei Template (`deos-open500-admin.yaml`)

## Vulnerability Information & PoC

## Description
The DEOS OPEN 500EMS controller exposes administrative functions without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/cosmobdf.cgi?function=0
GET {{BaseURL}}/cgi-bin/cosmobdf.cgi?function=1
```

## References
- https://www.deos-ag.com/
