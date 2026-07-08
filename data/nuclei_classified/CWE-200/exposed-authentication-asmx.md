# Vulnerability: Authentication.asmx - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-authentication-asmx.yaml`)

## Description
Authentication Web Service authentication.asmx file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_vti_bin/Authentication.asmx?op=Mode
```

