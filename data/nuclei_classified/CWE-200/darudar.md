# Vulnerability: Darudar User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`darudar.yaml`)

## Description
Darudar user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://darudar.org/users/{{user}}/
```

