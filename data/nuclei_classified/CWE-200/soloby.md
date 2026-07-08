# Vulnerability: Soloby User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`soloby.yaml`)

## Description
Soloby user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.soloby.ru/user/{{user}}
```

