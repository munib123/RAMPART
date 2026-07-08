# Vulnerability: Pypi User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pypi.yaml`)

## Description
Pypi user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pypi.org/user/{{user}}/
```

