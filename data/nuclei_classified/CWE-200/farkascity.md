# Vulnerability: Farkascity User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`farkascity.yaml`)

## Description
Farkascity user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://farkascity.org/{{user}}/
```

