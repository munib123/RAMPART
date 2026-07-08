# Vulnerability: Independent academia User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`independent-academia.yaml`)

## Description
Independent academia user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://independent.academia.edu/{{user}}
```

