# Vulnerability: HiHello User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hihello.yaml`)

## Description
HiHello user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.hihello.me/author/{{user}}
```

