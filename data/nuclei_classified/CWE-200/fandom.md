# Vulnerability: Fandom User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fandom.yaml`)

## Description
Fandom user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.fandom.com/u/{{user}}
```

