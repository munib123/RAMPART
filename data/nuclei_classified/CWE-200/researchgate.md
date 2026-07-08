# Vulnerability: Researchgate User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`researchgate.yaml`)

## Description
Researchgate user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.researchgate.net/profile/{{user}}
```

