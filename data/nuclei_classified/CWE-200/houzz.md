# Vulnerability: Houzz User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`houzz.yaml`)

## Description
Houzz user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.houzz.com/user/{{user}}
```

