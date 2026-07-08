# Vulnerability: Wanelo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wanelo.yaml`)

## Description
Wanelo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://wanelo.co/{{user}}
```

