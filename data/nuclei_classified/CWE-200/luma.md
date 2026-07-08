# Vulnerability: Luma User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`luma.yaml`)

## Description
Luma user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://lu.ma/user/{{user}}
```

