# Vulnerability: AtCoder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`atcoder.yaml`)

## Description
AtCoder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://atcoder.jp/users/{{user}}
```

