# Vulnerability: EToro User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`etoro.yaml`)

## Description
EToro user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.etoro.com/api/logininfo/v1.1/users/{{user}}
```

