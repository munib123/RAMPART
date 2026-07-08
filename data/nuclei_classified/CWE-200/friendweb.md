# Vulnerability: Friendweb User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`friendweb.yaml`)

## Description
Friendweb user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://friendweb.nl/{{user}}
```

