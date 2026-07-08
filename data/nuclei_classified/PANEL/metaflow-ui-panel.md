# Vulnerability: Metaflow UI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`metaflow-ui-panel.yaml`)

## Description
Metaflow is an open-source ML platform created by Netflix for building and managing real-life data science projects.
The Metaflow UI provides a web interface for monitoring and managing Metaflow runs and flows.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

