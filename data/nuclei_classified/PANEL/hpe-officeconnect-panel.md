# Vulnerability: HPE OfficeConnect Switch - Panel Detect
**Classification:** PANEL
**Source:** Nuclei Template (`hpe-officeconnect-panel.yaml`)

## Description
The HPE OfficeConnect Switch was a network switch series built for small and medium businesses.It provided reliable connectivity, simple management, and PoE options to support growing networks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

