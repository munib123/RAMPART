# Vulnerability: Ivanti Traffic Manager Panel - Detect
**Classification:** DETECT
**Source:** Nuclei Template (`ivanti-traffic-manager-panel.yaml`)

## Description
An Ivanti Traffic Manager Login Panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apps/zxtm/login.cgi
```

