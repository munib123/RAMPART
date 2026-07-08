# Vulnerability: Formalms Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`formalms-install.yaml`)

## Description
Formalms Installation is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

