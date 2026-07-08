# Vulnerability: SMA OpCon Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`sma-opcon-panel.yaml`)

## Description
SMA OpCon was detected — a workload automation and orchestration software.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/version
GET {{BaseURL}}/login
```

