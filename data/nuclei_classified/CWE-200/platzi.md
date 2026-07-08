# Vulnerability: Platzi service User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`platzi.yaml`)

## Description
Platzi service user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://platzi.com/p/{{user}}
```

