# Vulnerability: Dagster - Webserver UI Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`dagster-webserver-ui-exposure.yaml`)

## Description
Detected an exposed Dagster data orchestration webserver UI, potentially allowing unauthorized access to data pipelines, job configurations, and execution history.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

