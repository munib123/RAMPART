# Vulnerability: Carrd.co User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`carrdco.yaml`)

## Description
Carrd.co user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.carrd.co
```

