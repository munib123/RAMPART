# Vulnerability: Hoo.be User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hoobe.yaml`)

## Description
Hoo.be user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hoo.be/{{user}}
```

