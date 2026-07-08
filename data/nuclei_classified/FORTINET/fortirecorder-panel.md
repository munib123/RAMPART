# Vulnerability: FortiRecorder Panel - Detect
**Classification:** FORTINET
**Source:** Nuclei Template (`fortirecorder-panel.yaml`)

## Description
FortiRecorder Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/
```

