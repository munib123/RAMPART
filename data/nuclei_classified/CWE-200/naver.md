# Vulnerability: Naver User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`naver.yaml`)

## Description
Naver user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://blog.naver.com/{{user}}
```

