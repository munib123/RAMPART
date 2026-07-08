# Vulnerability: Moxa MXview One - Network Management Panel
**Classification:** PANEL
**Source:** Nuclei Template (`moxa-mxview-panel.yaml`)

## Description
Moxa MXview One is a network management platform for industrial Ethernet
infrastructure, OT network monitoring, and topology visualisation. It is
widely used in manufacturing, energy, and transportation to manage industrial
switches and routers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

