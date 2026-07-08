# Vulnerability: Tenor User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tenor.yaml`)

## Description
Tenor user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tenor.com/users/{{user}}
```

