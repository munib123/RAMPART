# Vulnerability: NiceGUI Detection
**Classification:** NICEGUI
**Source:** Nuclei Template (`nicegui-detect.yaml`)

## Description
An instance running NiceGUI is detected by looking for specific HTTP headers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

