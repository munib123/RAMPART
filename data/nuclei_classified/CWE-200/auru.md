# Vulnerability: Au.ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`auru.yaml`)

## Description
Au.ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://au.ru/user/{{user}}/
```

