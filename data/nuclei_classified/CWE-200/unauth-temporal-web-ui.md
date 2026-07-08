# Vulnerability: Temporal Web UI - Unauthenticated Access
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-temporal-web-ui.yaml`)

## Description
Temporal Web UI was able to be accessed because no authentication was required

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/favicon.ico
GET {{BaseURL}}/api/v1/namespaces/default/workflows?query=
```

