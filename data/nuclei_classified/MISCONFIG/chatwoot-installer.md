# Vulnerability: Chatwoot - Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`chatwoot-installer.yaml`)

## Description
Detected chatwoot instance with the initial installation onboarding page accessible at /installation/onboarding, enabling unauthenticated users to create the first Super Admin account and gain full platform control.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installation/onboarding
```

