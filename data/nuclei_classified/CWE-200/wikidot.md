# Vulnerability: Wikidot User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wikidot.yaml`)

## Description
Wikidot user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://www.wikidot.com/user:info/{{user}}
```

