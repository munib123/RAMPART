# Nuclei Template: Unauth Hawkeye Dashboard - Detect
**Template ID:** unauth-hawkeye-dashboard
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-hawkeye-dashboard.yaml`)

## Vulnerability Information & PoC

## Description
Hawkeye Dashboard was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/dashboard
```

