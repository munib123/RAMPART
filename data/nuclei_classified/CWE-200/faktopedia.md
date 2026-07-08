# Vulnerability: Faktopedia User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`faktopedia.yaml`)

## Description
Faktopedia user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://faktopedia.pl/user/{{user}}
```

