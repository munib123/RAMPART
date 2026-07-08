# Vulnerability: Heylink User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`heylink.yaml`)

## Description
Heylink user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://heylink.me/{{user}}/
```

