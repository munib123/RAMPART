# Vulnerability: Olx User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`olx.yaml`)

## Description
Olx user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.olx.pl/oferty/uzytkownik/{{user}}/
```

