# Vulnerability: Aspcms Backend Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`aspcms-backend-panel.yaml`)

## Description
ASPcms /plug/oem/AspCms_OEMFun.asp leak backend url.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /plug/oem/AspCms_OEMFun.asp  HTTP/1.1
Host: {{Hostname}}

GET {{path}}  HTTP/1.1
Host: {{Hostname}}
```

