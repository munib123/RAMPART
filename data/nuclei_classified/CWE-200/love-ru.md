# Vulnerability: Love ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`love-ru.yaml`)

## Description
Love ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://love.ru/{{user}}
```

