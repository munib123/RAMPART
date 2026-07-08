# Vulnerability: Hiberworld User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hiberworld.yaml`)

## Description
Hiberworld user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hiberworld.com/u/{{user}}
```

