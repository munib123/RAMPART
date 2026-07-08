# Vulnerability: Budibase - Admin Installer
**Classification:** EXPOSURE
**Source:** Nuclei Template (`budibase-admin-installer.yaml`)

## Description
Detected Budibase admin setup checklist endpoint was publicly accessible with no admin user created, allowing unauthenticated users to complete setup and gain full platform control.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/global/configs/checklist
```

