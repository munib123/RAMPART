# Vulnerability: VictoriaMetrics Panel - Detect
**Classification:** VICTORIAMETRICS
**Source:** Nuclei Template (`victoriametrics-panel.yaml`)

## Description
A VictoriaMetrics panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vmui/
```

