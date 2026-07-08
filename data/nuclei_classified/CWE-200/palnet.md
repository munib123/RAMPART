# Vulnerability: Palnet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`palnet.yaml`)

## Description
Palnet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.palnet.io/@{{user}}
```

