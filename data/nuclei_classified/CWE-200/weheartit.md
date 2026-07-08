# Vulnerability: Weheartit User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`weheartit.yaml`)

## Description
Weheartit user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://weheartit.com/{{user}}
```

