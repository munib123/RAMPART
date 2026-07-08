# Vulnerability: Cafecito User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cafecito.yaml`)

## Description
Cafecito user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cafecito.app/{{user}}
```

