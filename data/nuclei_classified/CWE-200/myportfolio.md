# Vulnerability: Myportfolio User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`myportfolio.yaml`)

## Description
Myportfolio user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.myportfolio.com/work
```

