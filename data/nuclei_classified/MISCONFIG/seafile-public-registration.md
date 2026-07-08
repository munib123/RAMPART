# Vulnerability: Seafile - Public Registration Enabled
**Classification:** MISCONFIG
**Source:** Nuclei Template (`seafile-public-registration.yaml`)

## Description
Detected public user registration is enabled on a Seafile instance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/accounts/register/
```

