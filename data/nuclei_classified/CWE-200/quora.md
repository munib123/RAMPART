# Vulnerability: Quora User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`quora.yaml`)

## Description
Quora user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.quora.com/profile/{{user}}
```

