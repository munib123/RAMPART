# Vulnerability: Medyczka.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`medyczkapl.yaml`)

## Description
Medyczka.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://medyczka.pl/user/{{user}}
```

