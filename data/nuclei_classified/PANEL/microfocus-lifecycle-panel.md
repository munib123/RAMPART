# Vulnerability: Micro Focus Application Lifecycle Management - Panel
**Classification:** PANEL
**Source:** Nuclei Template (`microfocus-lifecycle-panel.yaml`)

## Description
Micro Focus Application Lifecycle Management login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/qcbin/
```

