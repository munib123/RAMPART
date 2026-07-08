# Vulnerability: Unsplash User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unsplash.yaml`)

## Description
Unsplash user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://unsplash.com/@{{user}}
```

