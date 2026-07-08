# Vulnerability: Heimdall Application Dashboard - Unauthenticated Access
**Classification:** HEIMDALL
**Source:** Nuclei Template (`heimdall-dashboard-exposure.yaml`)

## Description
Detected The Heimdall Application Dashboard was accessible without authentication.When it was deployed without the protection, the full dashboard-including all linked internal services and API credentials-was accessible to unauthenticated users.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
Accept: text/html
```

