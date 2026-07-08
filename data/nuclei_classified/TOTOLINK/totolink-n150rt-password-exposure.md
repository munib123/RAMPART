# Vulnerability: TOTOLINK N150RT - Password Exposure
**Classification:** TOTOLINK
**Source:** Nuclei Template (`totolink-n150rt-password-exposure.yaml`)

## Description
Detects password exposure vulnerability in TOTOLINK N150RT router where sensitive credentials are exposed in the password.htm page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/password.htm
```

