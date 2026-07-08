# Vulnerability: Sitefinity Login
**Classification:** SITEFINITY
**Source:** Nuclei Template (`sitefinity-login.yaml`)

## Description
This template identifies the Sitefinity login page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Sitefinity/Authenticate/SWT
```

