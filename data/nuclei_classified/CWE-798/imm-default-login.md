# Vulnerability: Integrated Management Module - Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`imm-default-login.yaml`)

## Description
Integrated Management Module default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/data/login
```

