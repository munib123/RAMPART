# Vulnerability: FlexNet Operations Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`flexnet-operations-panel.yaml`)

## Description
FlexNet Operations was detected — a software monetization platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/flexnet/logon.do
```

