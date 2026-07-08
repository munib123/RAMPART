# Vulnerability: SABnzbd - Unauthenticated Web Interface Access
**Classification:** CWE-306
**Source:** Nuclei Template (`sabnzbd-unauth-access.yaml`)

## Description
Detected SABnzbd found with the web interface accessible without authentication. The config page is exposed without login, leaking the API key, config file path, server parameters, and system information to unauthenticated users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/
```

