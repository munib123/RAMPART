# Vulnerability: Zhihu User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zhihu.yaml`)

## Description
Zhihu user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.zhihu.com/people/{{user}}
```

