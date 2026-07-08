# Vulnerability: Kwejk.pl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kwejkpl.yaml`)

## Description
Kwejk.pl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://kwejk.pl/uzytkownik/{{user}}#/tablica/
```

