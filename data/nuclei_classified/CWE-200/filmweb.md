# Vulnerability: Filmweb User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`filmweb.yaml`)

## Description
Filmweb user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.filmweb.pl/user/{{user}}
```

