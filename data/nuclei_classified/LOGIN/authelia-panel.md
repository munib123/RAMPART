# Vulnerability: Authelia Panel - Detect
**Classification:** LOGIN
**Source:** Nuclei Template (`authelia-panel.yaml`)

## Description
Authelia is an open-source authentication and authorisation service providing two-factor authentication and single sign-on (SSO) for applications via a web portal.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

