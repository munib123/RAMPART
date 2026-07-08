# Vulnerability: Etsy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`etsy.yaml`)

## Description
Etsy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.etsy.com/people/{{user}}
```

