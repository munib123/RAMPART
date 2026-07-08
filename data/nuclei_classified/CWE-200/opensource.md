# Vulnerability: Opensource User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opensource.yaml`)

## Description
Opensource user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://opensource.com/users/{{user}}
```

