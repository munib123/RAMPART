# Vulnerability: SEL Real-Time Automation Controller - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`sel-rtac-panel.yaml`)

## Description
Schweitzer Engineering Laboratories (SEL) Real-Time Automation Controller (RTAC)
is a programmable automation controller used in electric utility and industrial
automation environments for protection, control, and automation. The web interface
exposes a management panel for configuration and monitoring.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

