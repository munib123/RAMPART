# Vulnerability: Bentbox User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bentbox.yaml`)

## Description
Bentbox user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bentbox.co/{{user}}
```

