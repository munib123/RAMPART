# Vulnerability: Cube-105 - Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`cube-105-install.yaml`)

## Description
Cube-105 is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizard/wizard.cs
```

