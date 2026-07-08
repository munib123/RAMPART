# Vulnerability: Smoothwall Firewall - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`smoothwall-firewall-panel.yaml`)

## Description
Smoothwall is a UK-based firewall and web filtering appliance commonly deployed in schools, local authorities, and enterprises for internet safety and network security management.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

