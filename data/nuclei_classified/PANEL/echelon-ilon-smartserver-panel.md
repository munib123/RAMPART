# Vulnerability: Echelon i.LON SmartServer - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`echelon-ilon-smartserver-panel.yaml`)

## Description
Echelon (now Adesto/Dialog Semiconductor) i.LON SmartServer is a LonWorks/IP-852
building automation controller used in HVAC, lighting, and energy management systems.
The embedded web interface is frequently exposed on standard and non-standard ports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

