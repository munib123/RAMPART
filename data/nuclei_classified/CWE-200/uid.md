# Vulnerability: Uid User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`uid.yaml`)

## Description
Uid user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://uid.me/{{user}}
```

