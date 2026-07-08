# Vulnerability: LibreSpeed Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`librespeed-panel.yaml`)

## Description
LibreSpeed is a very lightweight speed test implemented in Javascript, using XMLHttpRequest and Web Workers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

