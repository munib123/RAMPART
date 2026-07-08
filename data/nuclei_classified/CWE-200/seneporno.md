# Vulnerability: Seneporno User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`seneporno.yaml`)

## Description
Seneporno user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://seneporno.com/user/{{user}}
```

