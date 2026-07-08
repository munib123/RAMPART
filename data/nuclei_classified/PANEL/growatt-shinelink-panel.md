# Vulnerability: Growatt Shinelink - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`growatt-shinelink-panel.yaml`)

## Description
Growatt Shinelink is a web-based data logger and monitoring interface for Growatt solar inverters, providing real-time solar energy production data and system configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

