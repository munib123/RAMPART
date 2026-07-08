# Vulnerability: Multilaser Pro Setup Page - Detect
**Classification:** MISCONFIG
**Source:** Nuclei Template (`multilaser-pro-setup.yaml`)

## Description
This allows the user to access quick setup settings and configuration page through /wizard.htm.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizard.htm
```

