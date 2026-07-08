# Vulnerability: Kongregate User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kongregate.yaml`)

## Description
Kongregate user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.kongregate.com/accounts/{{user}}
```

