# Vulnerability: Wordnik User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wordnik.yaml`)

## Description
Wordnik user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.wordnik.com/users/{{user}}
```

