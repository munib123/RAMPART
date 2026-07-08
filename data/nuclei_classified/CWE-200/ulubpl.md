# Vulnerability: Ulub.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ulubpl.yaml`)

## Description
Ulub.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://ulub.pl/profil/{{user}}
```

