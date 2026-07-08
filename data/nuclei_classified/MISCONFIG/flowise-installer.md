# Vulnerability: Flowise Installation Wizard - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`flowise-installer.yaml`)

## Description
Flowise Installation Wizard is susceptible to the Installation page exposure due to misconfiguration

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/organization-setup
POST /api/v1/account/register HTTP/1.1
Host: {{Hostname}}

{"user":{"name":"{{name}}","email":"{{email}}","type":"pro","credential":"{{password}}"}}
```

