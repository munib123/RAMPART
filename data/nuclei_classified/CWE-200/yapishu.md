# Vulnerability: Yapishu User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`yapishu.yaml`)

## Description
Yapishu user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://yapishu.net/user/{{user}}
```

