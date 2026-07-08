# Vulnerability: OpenBao Web UI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`openbao-webui-detect.yaml`)

## Description
Detects the presence of the OpenBao web console.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui
```

