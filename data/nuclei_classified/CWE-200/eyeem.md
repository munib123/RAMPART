# Vulnerability: Eyeem User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`eyeem.yaml`)

## Description
Eyeem user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.eyeem.com/u/{{user}}
```

