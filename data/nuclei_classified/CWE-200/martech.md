# Vulnerability: Martech User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`martech.yaml`)

## Description
Martech user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://martech.org/author/{{user}}/
```

