# Vulnerability: Dfgames User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dfgames.yaml`)

## Description
Dfgames user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.dfgames.com.br/user/{{user}}
```

