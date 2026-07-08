# Vulnerability: SEO King - Shopify App — Installer
**Classification:** MISCONFIG
**Source:** Nuclei Template (`shopify-app-installer.yaml`)

## Description
Shopify App is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

