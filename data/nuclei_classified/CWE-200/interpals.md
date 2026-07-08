# Vulnerability: Interpals User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`interpals.yaml`)

## Description
Interpals user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.interpals.net/{{user}}
```

