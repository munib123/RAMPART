# Vulnerability: CD-Action User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cd-action.yaml`)

## Description
CD-Action user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cdaction.pl/uzytkownicy/{{user}}
```

