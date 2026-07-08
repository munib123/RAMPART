# Vulnerability: Fanpop User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fanpop.yaml`)

## Description
Fanpop user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.fanpop.com/fans/{{user}}
```

