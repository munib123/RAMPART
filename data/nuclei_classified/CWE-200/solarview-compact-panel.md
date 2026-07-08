# Vulnerability: SolarView Compact Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`solarview-compact-panel.yaml`)

## Description
SolarView Compact panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Solar_Menu.php
```

