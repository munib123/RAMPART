# Vulnerability: 21buttons User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`21buttons.yaml`)

## Description
21buttons user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.21buttons.com/buttoner/{{user}}
```

