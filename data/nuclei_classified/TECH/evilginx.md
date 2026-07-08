# Vulnerability: EvilGinx - Detect
**Classification:** TECH
**Source:** Nuclei Template (`evilginx.yaml`)

## Description
Evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies which in turn allows bypassing 2-factor authentication protection.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

