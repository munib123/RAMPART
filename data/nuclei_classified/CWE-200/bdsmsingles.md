# Vulnerability: Bdsmsingles User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bdsmsingles.yaml`)

## Description
Bdsmsingles user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.bdsmsingles.com/members/{{user}}/
```

