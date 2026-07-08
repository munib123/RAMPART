# Vulnerability: Schneider Electric ClearSCADA - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`clearscada-panel.yaml`)

## Description
ClearSCADA (now branded as EcoStruxure Geo SCADA Expert) is a Schneider Electric
SCADA platform used in water, oil and gas, and utilities sectors. Exposed instances
may provide unauthenticated access to industrial process data and control interfaces.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

