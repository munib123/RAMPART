# Vulnerability: Instructables User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`instructables.yaml`)

## Description
Instructables user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.instructables.com/member/{{user}}/
```

