# Vulnerability: Chamsko User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`chamsko.yaml`)

## Description
Chamsko user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.chamsko.pl/profil/{{user}}
```

