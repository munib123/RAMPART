# Vulnerability: Tautulli - Exposed Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`tautulli-install.yaml`)

## Description
Tautulli is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/welcome
```

