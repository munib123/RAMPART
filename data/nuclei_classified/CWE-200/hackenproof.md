# Vulnerability: Hackenproof User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hackenproof.yaml`)

## Description
Hackenproof user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://hackenproof.com/hackers/{{user}}
```

