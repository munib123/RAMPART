# Vulnerability: Albicla User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`albicla.yaml`)

## Description
Albicla user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://albicla.com/{{user}}/post/1
```

