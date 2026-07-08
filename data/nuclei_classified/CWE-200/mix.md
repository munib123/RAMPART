# Vulnerability: Mix User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mix.yaml`)

## Description
Mix user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mix.com/{{user}}/
```

