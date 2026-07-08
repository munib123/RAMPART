# Vulnerability: Jeja.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jejapl.yaml`)

## Description
Jeja.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.jeja.pl/user,{{user}}
```

