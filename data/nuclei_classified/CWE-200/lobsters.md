# Vulnerability: Lobste.rs User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lobsters.yaml`)

## Description
Lobste.rs user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://lobste.rs/u/{{user}}
```

