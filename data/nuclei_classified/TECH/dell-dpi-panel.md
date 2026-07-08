# Vulnerability: Dell DPI Remote Power Management - Detect
**Classification:** TECH
**Source:** Nuclei Template (`dell-dpi-panel.yaml`)

## Description
The Dell Metered Rack Power Distribution Unit distributes power to a server rack and are installed at the rear of a rack enclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index2.html
```

