# Nuclei Template: SABnzbd - Unauthenticated Web Interface Access
**Template ID:** sabnzbd-unauth-access
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** High
**CWE:** CWE-306
**Source:** Nuclei Template (`sabnzbd-unauth-access.yaml`)

## Vulnerability Information & PoC

## Description
Detected SABnzbd found with the web interface accessible without authentication. The config page is exposed without login, leaking the API key, config file path, server parameters, and system information to unauthenticated users.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/
```

## References
- https://sabnzbd.org/wiki/extra/access-denied.html
- https://sabnzbd.org/wiki/configuration/4.5/api
