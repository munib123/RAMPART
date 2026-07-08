# Vulnerability: Telegram User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`telegram.yaml`)

## Description
Telegram user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://t.me/{{user}}
```

