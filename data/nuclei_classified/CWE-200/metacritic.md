# Vulnerability: Metacritic User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`metacritic.yaml`)

## Description
Metacritic user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.metacritic.com/user/{{user}}
```

