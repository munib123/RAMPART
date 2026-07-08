# Vulnerability: Iconfinder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`iconfinder.yaml`)

## Description
Iconfinder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.iconfinder.com/{{user}}
```

