# Vulnerability: ScadaBR - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`scadabr-panel.yaml`)

## Description
ScadaBR is an open-source SCADA system based on Mango Automation, widely
used in Brazil and Latin America for industrial monitoring. The "powered by
Mango" tagline in the title is a unique identifier. Instances are often
internet-facing without authentication controls.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

