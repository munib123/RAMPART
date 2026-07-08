# Vulnerability: 9GAG User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`9gag.yaml`)

## Description
9GAG user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.9gag.com/u/{{user}}
```

