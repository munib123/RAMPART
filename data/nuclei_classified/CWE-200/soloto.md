# Vulnerability: Solo.to User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`soloto.yaml`)

## Description
Solo.to user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://solo.to/{{user}}
```

