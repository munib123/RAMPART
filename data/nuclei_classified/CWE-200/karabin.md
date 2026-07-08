# Vulnerability: Karab.in User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`karabin.yaml`)

## Description
Karab.in user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://karab.in/u/{{user}}
```

