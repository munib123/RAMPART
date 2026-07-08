# Vulnerability: Linktree User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`linktree.yaml`)

## Description
Linktree user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://linktr.ee/{{user}}
```

