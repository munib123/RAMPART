# Vulnerability: Ifunny User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ifunny.yaml`)

## Description
Ifunny user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ifunny.co/user/{{user}}
```

