# Vulnerability: ESPHome Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`esphome-panel.yaml`)

## Description
ESPHome login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

