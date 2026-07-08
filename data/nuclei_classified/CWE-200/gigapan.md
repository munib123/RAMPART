# Vulnerability: Gigapan User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gigapan.yaml`)

## Description
Gigapan user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.gigapan.com/profiles/{{user}}
```

