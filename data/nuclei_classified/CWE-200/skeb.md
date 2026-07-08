# Vulnerability: Skeb User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`skeb.yaml`)

## Description
Skeb user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://skeb.jp/@{{user}}
```

