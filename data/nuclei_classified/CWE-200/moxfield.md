# Vulnerability: Moxfield User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`moxfield.yaml`)

## Description
Moxfield user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.moxfield.com/users/{{user}}
```

