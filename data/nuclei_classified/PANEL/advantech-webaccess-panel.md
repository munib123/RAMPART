# Vulnerability: Advantech WebAccess/SCADA - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`advantech-webaccess-panel.yaml`)

## Description
Detected Advantech WebAccess/SCADA login panel, a web-browser-based HMI/SCADA software used in critical manufacturing, energy, and water systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/broadWeb/bwRoot.asp
```

