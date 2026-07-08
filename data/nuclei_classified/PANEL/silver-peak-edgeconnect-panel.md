# Vulnerability: Silver Peak / HPE Aruba EdgeConnect - Orchestrator Panel
**Classification:** PANEL
**Source:** Nuclei Template (`silver-peak-edgeconnect-panel.yaml`)

## Description
Silver Peak (now HPE Aruba Networking) EdgeConnect SD-WAN Orchestrator is a
centralised management platform for EdgeConnect SD-WAN appliances. The web portal
is commonly exposed on HTTPS ports including 8443.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

