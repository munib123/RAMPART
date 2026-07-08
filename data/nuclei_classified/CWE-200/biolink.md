# Vulnerability: Biolink User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`biolink.yaml`)

## Description
Biolink user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bio.link/{{user}}
```

