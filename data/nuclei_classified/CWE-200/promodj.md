# Vulnerability: Promodj User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`promodj.yaml`)

## Description
Promodj user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://promodj.com/{{user}}
```

