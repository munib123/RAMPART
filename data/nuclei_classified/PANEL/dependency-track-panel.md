# Vulnerability: Dependency-Track Login - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`dependency-track-panel.yaml`)

## Description
Dependency Track login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?redirect=%2Fdashboard
```

