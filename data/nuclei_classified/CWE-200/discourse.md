# Vulnerability: Discourse User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`discourse.yaml`)

## Description
Discourse user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://meta.discourse.org/u/{{user}}/summary.json
```

