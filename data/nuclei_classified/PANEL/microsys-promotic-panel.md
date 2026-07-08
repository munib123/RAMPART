# Vulnerability: Microsys Promotic SCADA - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`microsys-promotic-panel.yaml`)

## Description
Microsys Promotic is a SCADA/HMI software platform widely deployed in central European
industrial and building automation applications. The embedded web server exposes a
runtime panel accessible over HTTP on non-standard ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

