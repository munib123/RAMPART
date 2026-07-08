# Vulnerability: Yacht Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`yacht-panel.yaml`)

## Description
Yacht is a web management platform for managing Docker containers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

