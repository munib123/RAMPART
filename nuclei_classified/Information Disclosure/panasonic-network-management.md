# Nuclei Template: Panasonic Network Camera Management System - Detect
**Template ID:** panasonic-network-management
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`panasonic-network-management.yaml`)

## Vulnerability Information & PoC

## Description
Panasonic Network Camera Management System page with live views was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/cam_portal.cgi
```

## References
- https://www.exploit-db.com/ghdb/6487
