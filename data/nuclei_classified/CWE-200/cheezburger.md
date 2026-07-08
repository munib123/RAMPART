# Vulnerability: CHEEZburger User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cheezburger.yaml`)

## Description
CHEEZburger user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://profile.cheezburger.com/{{user}}
```

