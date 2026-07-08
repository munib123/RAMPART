# Vulnerability: Motokiller User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`motokiller.yaml`)

## Description
Motokiller user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mklr.pl/user/{{user}}
```

