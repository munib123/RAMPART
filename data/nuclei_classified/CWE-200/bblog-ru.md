# Vulnerability: Bblog ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bblog-ru.yaml`)

## Description
Bblog ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.babyblog.ru/user/{{user}}
```

