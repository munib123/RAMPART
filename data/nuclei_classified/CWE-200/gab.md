# Vulnerability: Gab User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gab.yaml`)

## Description
Gab user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gab.com/api/v1/account_by_username/{{user}}
```

