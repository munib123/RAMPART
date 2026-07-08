# Vulnerability: Easyen User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`easyen.yaml`)

## Description
Easyen user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://easyen.ru/index/8-0-{{user}}
```

