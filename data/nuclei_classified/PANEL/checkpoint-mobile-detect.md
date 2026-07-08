# Vulnerability: Check Point Mobile SSL VPN - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`checkpoint-mobile-detect.yaml`)

## Description
Check Point Mobile SSL VPN was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/sslvpn/Login
```

