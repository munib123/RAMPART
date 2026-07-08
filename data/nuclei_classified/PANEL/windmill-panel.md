# Vulnerability: Windmill Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`windmill-panel.yaml`)

## Description
Windmill panel was detected. Windmill (windmill.dev) is an open-source developer platform for workflows, scripts and internal apps, often self-hosted as a Postgres-backed UI. Exposed instances may reveal scripts, secrets and connected resources, and provide an authenticated path to script execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/version
```

