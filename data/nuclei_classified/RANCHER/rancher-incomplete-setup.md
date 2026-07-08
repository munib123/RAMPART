# Vulnerability: Rancher - Incomplete Setup Exposure
**Classification:** RANCHER
**Source:** Nuclei Template (`rancher-incomplete-setup.yaml`)

## Description
Detected Rancher installation was found with an incomplete first-time setup. The bootstrap login page was publicly accessible at /dashboard/auth/login, indicating an unconfigured instance that could have been targeted for unauthorized setup completion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v3/settings/first-login
```

