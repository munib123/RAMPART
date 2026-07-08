# Vulnerability: Hackaday User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hackaday.yaml`)

## Description
Hackaday user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hackaday.io/{{user}}
```

