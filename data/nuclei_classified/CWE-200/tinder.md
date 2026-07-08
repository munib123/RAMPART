# Vulnerability: Tinder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tinder.yaml`)

## Description
Tinder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tinder.com/@{{user}}
```

