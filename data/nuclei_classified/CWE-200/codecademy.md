# Vulnerability: Codecademy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`codecademy.yaml`)

## Description
Codecademy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://discuss.codecademy.com/u/{{user}}/summary
```

