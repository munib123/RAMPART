# Vulnerability: Ubisoft User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ubisoft.yaml`)

## Description
Ubisoft user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://discussions.ubisoft.com/user/{{user}}
```

