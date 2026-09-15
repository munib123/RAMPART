# Nuclei Template: Dagster - Webserver UI Exposure
**Template ID:** dagster-webserver-ui-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`dagster-webserver-ui-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected an exposed Dagster data orchestration webserver UI, potentially allowing unauthorized access to data pipelines, job configurations, and execution history.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/
```

## References
- https://dagster.io/
- https://github.com/dagster-io/dagster
