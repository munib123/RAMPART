# Vulnerability: 3dtoday User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`3dtoday.yaml`)

## Description
3dtoday user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://3dtoday.ru/blogs/{{user}}
```

