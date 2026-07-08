# Vulnerability: Gist User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gist.yaml`)

## Description
Gist user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gist.github.com/{{user}}
```

