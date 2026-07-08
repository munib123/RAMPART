# Vulnerability: Issuu User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`issuu.yaml`)

## Description
Issuu user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://issuu.com/{{user}}
```

