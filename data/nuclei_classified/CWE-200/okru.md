# Vulnerability: Ok.ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`okru.yaml`)

## Description
Ok.ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ok.ru/{{user}}
```

