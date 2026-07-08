# Vulnerability: CODESYS WebVisu - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`codesys-webvisu-panel.yaml`)

## Description
CODESYS WebVisu is the web-based HMI (Human-Machine Interface) component of the
CODESYS industrial automation runtime. It provides browser-based access to PLC
visualizations and industrial control interfaces. Exposed instances may reveal
real-time process data and control functions without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

