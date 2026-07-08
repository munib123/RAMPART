# Vulnerability: Audiojungle User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`audiojungle.yaml`)

## Description
Audiojungle user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://audiojungle.net/user/{{user}}
```

