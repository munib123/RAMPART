# Vulnerability: GE Proficy WebSpace - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`ge-proficy-webspace-panel.yaml`)

## Description
GE Proficy WebSpace is a thin-client delivery platform for GE Proficy
HMI/SCADA (iFIX, CIMPLICITY) applications over the web. It exposes
industrial HMI screens via browser on TCP/491 by default. The Server
header "WebSocket++/0.7.0" is a unique indicator.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

