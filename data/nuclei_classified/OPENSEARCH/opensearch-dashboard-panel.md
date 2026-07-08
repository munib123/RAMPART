# Vulnerability: OpenSearch Dashboard Panel - Detect
**Classification:** OPENSEARCH
**Source:** Nuclei Template (`opensearch-dashboard-panel.yaml`)

## Description
OpenSearch Dashboard is a visualization and management tool for OpenSearch. This template detects the presence of the OpenSearch Dashboard login panel, which is the default authentication interface for accessing the dashboard.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/app/login?
```

