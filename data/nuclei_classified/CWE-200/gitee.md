# Vulnerability: Gitee User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gitee.yaml`)

## Description
Gitee user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gitee.com/{{user}}
```

