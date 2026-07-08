# Vulnerability: BeyondTrust Privileged Remote Access - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`beyondtrust-priv-panel.yaml`)

## Description
BeyondTrust Privileged Remote Access login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/login
GET {{BaseURL}}/login/pre_login_agreement
```

