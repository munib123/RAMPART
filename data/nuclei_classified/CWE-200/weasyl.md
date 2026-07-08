# Vulnerability: Weasyl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`weasyl.yaml`)

## Description
Weasyl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.weasyl.com/~{{user}}
```

