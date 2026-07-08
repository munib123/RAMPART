# Vulnerability: Scribd User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`scribd.yaml`)

## Description
Scribd user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.scribd.com/{{user}}
```

