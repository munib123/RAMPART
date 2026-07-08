# Vulnerability: Mixi User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mixi.yaml`)

## Description
Mixi user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mixi.jp/view_community.pl?id={{user}}
```

