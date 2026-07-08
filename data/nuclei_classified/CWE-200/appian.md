# Vulnerability: Appian User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`appian.yaml`)

## Description
Appian user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://community.appian.com/members/{{user}}
```

