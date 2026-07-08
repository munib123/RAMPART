# Vulnerability: Salon24 User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`salon24.yaml`)

## Description
Salon24 user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.salon24.pl/u/{{user}}/
```

