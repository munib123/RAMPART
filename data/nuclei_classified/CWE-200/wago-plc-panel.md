# Vulnerability: WAGO PLC Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wago-plc-panel.yaml`)

## Description
WAGO PLC panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plc/webvisu.htm
```

