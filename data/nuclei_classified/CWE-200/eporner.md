# Vulnerability: EPORNER User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`eporner.yaml`)

## Description
EPORNER user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.eporner.com/profile/{{user}}/
```

