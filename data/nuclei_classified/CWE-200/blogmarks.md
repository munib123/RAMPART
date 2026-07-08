# Vulnerability: Blogmarks User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blogmarks.yaml`)

## Description
Blogmarks user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://blogmarks.net/user/{{user}}
```

