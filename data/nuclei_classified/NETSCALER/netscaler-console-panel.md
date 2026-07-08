# Vulnerability: NetScaler Console - Panel
**Classification:** NETSCALER
**Source:** Nuclei Template (`netscaler-console-panel.yaml`)

## Description
NetScaler Console login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin_ui/mas/ent/login.html
```

