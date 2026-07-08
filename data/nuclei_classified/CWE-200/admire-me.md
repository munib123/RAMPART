# Vulnerability: Admire me User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`admire-me.yaml`)

## Description
Admire me user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://admireme.vip/{{user}}/
```

