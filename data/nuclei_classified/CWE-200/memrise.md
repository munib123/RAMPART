# Vulnerability: Memrise User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`memrise.yaml`)

## Description
Memrise user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://app.memrise.com/user/{{user}}/
```

