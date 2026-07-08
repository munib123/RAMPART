# Vulnerability: Apteka User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apteka.yaml`)

## Description
Apteka user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://apteka.ee/user/id/{{user}}
```

