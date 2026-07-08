# Vulnerability: Dating.ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`datingru.yaml`)

## Description
Dating.ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://dating.ru/{{user}}/
```

