# Vulnerability: GitHub User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`github.yaml`)

## Description
GitHub user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://github.com/{{user}}
```

