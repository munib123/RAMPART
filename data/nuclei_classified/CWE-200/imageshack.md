# Vulnerability: ImageShack User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`imageshack.yaml`)

## Description
ImageShack user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://imageshack.com/user/{{user}}
```

