# Vulnerability: Destructoid User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`destructoid.yaml`)

## Description
Destructoid user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.destructoid.com/?name={{user}}
```

