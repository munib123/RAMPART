# Vulnerability: Reliable Controls MACH-Pro - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`reliable-controls-panel.yaml`)

## Description
Reliable Controls MACH-ProWebSys is a web-based building controller for
HVAC, lighting, and energy management using BACnet/IP. These controllers
are widely deployed in commercial buildings across North America and are
often directly internet-facing with no VPN protection.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

