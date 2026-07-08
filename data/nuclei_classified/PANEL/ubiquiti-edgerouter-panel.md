# Vulnerability: Ubiquiti EdgeRouter - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`ubiquiti-edgerouter-panel.yaml`)

## Description
Ubiquiti EdgeRouter is an enterprise-grade router with advanced routing capabilities and VPN features, running EdgeOS (Ubiquiti's Vyatta-based firmware).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

