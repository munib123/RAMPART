# Vulnerability: DevRant User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`devrant.yaml`)

## Description
DevRant user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://devrant.com/users/{{user}}
```

