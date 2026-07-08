# Vulnerability: Weibo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`weibo.yaml`)

## Description
Weibo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tw.weibo.com/{{user}}
```

