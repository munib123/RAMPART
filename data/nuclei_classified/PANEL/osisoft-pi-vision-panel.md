# Vulnerability: OSIsoft PI Vision - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`osisoft-pi-vision-panel.yaml`)

## Description
OSIsoft PI Vision (now AVEVA PI Vision) is a web-based data visualisation
platform for the PI System, widely used in energy, utilities, oil and gas,
and manufacturing for real-time operational data monitoring. Exposed instances
may provide access to sensitive operational technology data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

