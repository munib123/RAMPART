# Vulnerability: Airbyte Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`airbyte-panel.yaml`)

## Description
Airbyte panel was detected. Airbyte is a popular open-source data integration platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/v1/health
```

