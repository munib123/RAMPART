# Vulnerability: UniGUI Server Monitor Panel - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`unigui-server-monitor-exposure.yaml`)

## Description
Detects exposed UniGUI Server Monitor Panels which could reveal sensitive server statistics, users sessions, licensing information and others data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/server
```

