# Vulnerability: XAMPP Environment Variables Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`xampp-environment-variables.yaml`)

## Description
printenv.pl file is exposed in XAMPP leaking environment variables.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/printenv.pl
```

