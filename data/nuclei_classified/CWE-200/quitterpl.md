# Vulnerability: Quitter.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`quitterpl.yaml`)

## Description
Quitter.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://quitter.pl/profile/{{user}}
```

