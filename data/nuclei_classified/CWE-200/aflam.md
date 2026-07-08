# Vulnerability: Aflam User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`aflam.yaml`)

## Description
Aflam user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.aflam4you.net/profile.html?u={{user}}
```

