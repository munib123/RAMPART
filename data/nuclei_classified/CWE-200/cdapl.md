# Vulnerability: Cda.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cdapl.yaml`)

## Description
Cda.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.cda.pl/{{user}}
```

