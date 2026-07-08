# Vulnerability: Zmarsa.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zmarsacom.yaml`)

## Description
Zmarsa.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://zmarsa.com/uzytkownik/{{user}}/glowna/
```

