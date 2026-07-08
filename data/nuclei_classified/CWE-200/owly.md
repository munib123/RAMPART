# Vulnerability: Ow.ly User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`owly.yaml`)

## Description
Ow.ly user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://ow.ly/user/{{user}}
```

