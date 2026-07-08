# Vulnerability: Cogent DataHub (OPC DataHub) - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`cogent-datahub-panel.yaml`)

## Description
Cogent DataHub (OPC DataHub) is an industrial middleware platform for OPC connectivity,
data bridging, and SCADA integration. The embedded web server is commonly exposed on
port 80 or 443.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

