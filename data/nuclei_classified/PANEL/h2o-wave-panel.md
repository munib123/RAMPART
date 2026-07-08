# Vulnerability: H2O Wave ML Application Server - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`h2o-wave-panel.yaml`)

## Description
H2O Wave was detected. H2O Wave was an open-source Python development framework for building real-time interactive AI and ML web applications. The Wave server hosted applications built on the platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

