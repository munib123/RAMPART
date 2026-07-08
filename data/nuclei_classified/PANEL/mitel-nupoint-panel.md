# Vulnerability: Mitel NuPoint Unified Messaging Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mitel-nupoint-panel.yaml`)

## Description
Mitel NuPoint Unified Messaging login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/npm-admin/showLoginPage.do
```

