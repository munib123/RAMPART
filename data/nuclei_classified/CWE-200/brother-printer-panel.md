# Vulnerability: Brother Printer Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`brother-printer-panel.yaml`)

## Description
Brother printer web interface and management panel was detected. This template identifies exposed Brother printer panels that may be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/general/status.html
```

