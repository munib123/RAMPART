# Vulnerability: Pulsar Admin UI Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pulsar-adminui-panel.yaml`)

## Description
Pulsar admin UI panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login?redirect=%2F
```

