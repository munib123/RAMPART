# Vulnerability: NotABug User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`notabug.yaml`)

## Description
NotABug user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://notabug.org/{{user}}
```

