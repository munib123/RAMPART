# Vulnerability: Pronouny User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pronouny.yaml`)

## Description
Pronouny user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pronouny.xyz/api/users/profile/username/{{user}}
```

