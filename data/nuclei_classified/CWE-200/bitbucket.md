# Vulnerability: Bitbucket User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bitbucket.yaml`)

## Description
Bitbucket user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bitbucket.org/{{user}}/
```

