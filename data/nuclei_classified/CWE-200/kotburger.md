# Vulnerability: Kotburger User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kotburger.yaml`)

## Description
Kotburger user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://kotburger.pl/user/{{user}}
```

