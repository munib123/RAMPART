# Vulnerability: FatSecret User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fatsecret.yaml`)

## Description
FatSecret user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.fatsecret.com/member/{{user}}
```

