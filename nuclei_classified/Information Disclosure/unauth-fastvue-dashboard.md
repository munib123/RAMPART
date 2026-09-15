# Nuclei Template: Fastvue Dashboard Panel - Unauthenticated Detect
**Template ID:** unauth-fastvue-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-fastvue-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Fastvue Dashboard panel was detected without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/dashboard.aspx
```

