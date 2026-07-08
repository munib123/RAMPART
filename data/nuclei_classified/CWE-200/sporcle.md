# Vulnerability: Sporcle User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sporcle.yaml`)

## Description
Sporcle user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.sporcle.com/user/{{user}}/people/
```

