# Vulnerability: Untangle Exposed Admin Signup
**Classification:** MISCONFIG
**Source:** Nuclei Template (`untangle-admin-setup.yaml`)

## Description
Untangle Exposed Admin Signup is exposed publicly.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/setup.do
```

