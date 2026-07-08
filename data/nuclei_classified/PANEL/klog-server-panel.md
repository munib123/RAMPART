# Vulnerability: Klog Server Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`klog-server-panel.yaml`)

## Description
Klog Server panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.php
```

