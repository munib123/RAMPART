# Vulnerability: Kaskus User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kaskus.yaml`)

## Description
Kaskus user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.kaskus.co.id/@{{user}}
```

