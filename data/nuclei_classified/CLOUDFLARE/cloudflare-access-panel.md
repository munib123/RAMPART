# Vulnerability: Cloudflare Access - Login Panel Detection
**Classification:** CLOUDFLARE
**Source:** Nuclei Template (`cloudflare-access-panel.yaml`)

## Description
Detected exposed Cloudflare Access login pages.

## Secure Mitigation
- Ensure Cloudflare Access policies are properly configured to restrict access to authorized users only
- Review and enforce appropriate authentication rules and multi-factor authentication requirements
- Limit exposure of Access login pages to necessary endpoints only

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

