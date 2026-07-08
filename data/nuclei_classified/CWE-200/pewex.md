# Vulnerability: Pewex User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pewex.yaml`)

## Description
Pewex user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://retro.pewex.pl/user/{{user}}
```

