# Vulnerability: Stormshield Network Security - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`stormshield-network-security-panel.yaml`)

## Description
Stormshield Network Security (SNS) is a French network security appliance providing
firewall, IPS, VPN, and web filtering capabilities. Its web management portal is
frequently exposed on non-standard ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin
GET {{BaseURL}}/admin/admin.html
```

