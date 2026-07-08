# Vulnerability: Odoo - Detect
**Classification:** TECH
**Source:** Nuclei Template (`odoo-detect.yaml`)

## Description
Detected Odoo by sending an empty JSON POST request to the /web/webclient/version_info endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /web/webclient/version_info HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{}
```

