# Vulnerability: Drum User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`drum.yaml`)

## Description
Drum user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://drum.io/{{user}}/
```

