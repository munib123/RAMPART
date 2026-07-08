# Vulnerability: Janitza UMG Power Meter - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`janitza-umg-panel.yaml`)

## Description
Janitza UMG series power meters and energy analyzers expose a web interface for energy monitoring and power quality analysis.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

