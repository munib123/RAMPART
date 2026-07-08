# Vulnerability: Poll Everywhere User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`poll-everywhere.yaml`)

## Description
Poll Everywhere user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pollev.com/proxy/api/users/{{user}}
```

