# Vulnerability: F5 BIG-IP iControl REST Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bigip-rest-panel.yaml`)

## Description
F5 BIG-IP iControl REST API discovered and may be vulnerable to an authentication bypass (not tested).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mgmt/shared/authn/login
```

