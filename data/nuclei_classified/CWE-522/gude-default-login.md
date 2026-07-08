# Vulnerability: GUDE - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`gude-default-login.yaml`)

## Description
GUDE 2301 and 2302 default administrator login credentials (admin:admin) were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ov.html?
```

