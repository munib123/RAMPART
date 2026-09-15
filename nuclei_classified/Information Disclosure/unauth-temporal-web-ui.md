# Nuclei Template: Temporal Web UI - Unauthenticated Access
**Template ID:** unauth-temporal-web-ui
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-temporal-web-ui.yaml`)

## Vulnerability Information & PoC

## Description
Temporal Web UI was able to be accessed because no authentication was required

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/api/v1/namespaces/default/workflows?query=
```

## References
- https://docs.temporal.io/web-ui
