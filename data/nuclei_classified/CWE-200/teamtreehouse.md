# Vulnerability: Teamtreehouse User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teamtreehouse.yaml`)

## Description
Teamtreehouse user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://teamtreehouse.com/{{user}}
```

