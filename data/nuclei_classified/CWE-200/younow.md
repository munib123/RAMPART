# Vulnerability: YouNow User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`younow.yaml`)

## Description
YouNow user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.younow.com/{{user}}/
```

