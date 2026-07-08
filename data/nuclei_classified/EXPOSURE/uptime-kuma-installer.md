# Vulnerability: Uptime Kuma - Installer
**Classification:** EXPOSURE
**Source:** Nuclei Template (`uptime-kuma-installer.yaml`)

## Description
Detected Uptime Kuma setup page is publicly accessible with needSetup enabled, allowing unauthenticated users to complete installation and gain full admin access by access /setup-database.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup-database-info
```

