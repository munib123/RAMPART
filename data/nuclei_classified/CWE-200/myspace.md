# Vulnerability: MySpace User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`myspace.yaml`)

## Description
MySpace user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://myspace.com/{{user}}
```

