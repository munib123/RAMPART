# Vulnerability: Blinko - Login Panel Detection
**Classification:** PANEL
**Source:** Nuclei Template (`blinko-login-panel.yaml`)

## Description
Detected A Blinko self-hosted personal note application login panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/signin
```

