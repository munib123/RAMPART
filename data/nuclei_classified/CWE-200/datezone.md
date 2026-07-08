# Vulnerability: Datezone User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`datezone.yaml`)

## Description
Datezone user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.datezone.com/users/{{user}}/
```

