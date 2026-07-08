# Vulnerability: Getmonero User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`getmonero.yaml`)

## Description
Getmonero user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forum.getmonero.org/user/{{user}}
```

