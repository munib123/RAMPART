# Vulnerability: Security Onion Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`security-onion-panel.yaml`)

## Description
Security Onion is a free and open source Linux distribution for intrusion detection, security monitoring, and log management. It includes CyberChef, NetworkMiner, and many other security tools.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/login/
```

