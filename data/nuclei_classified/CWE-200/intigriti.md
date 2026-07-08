# Vulnerability: Intigriti User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`intigriti.yaml`)

## Description
Intigriti user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://app.intigriti.com/profile/{{user}}
```

