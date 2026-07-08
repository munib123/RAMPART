# Vulnerability: Cracked io User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cracked-io.yaml`)

## Description
Cracked io user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cracked.io/{{user}}
```

