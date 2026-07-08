# Vulnerability: Oglaszamy24h.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oglaszamy24hpl.yaml`)

## Description
Oglaszamy24h.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://oglaszamy24h.pl/profil,{{user}}
```

