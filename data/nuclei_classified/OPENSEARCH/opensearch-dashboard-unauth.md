# Vulnerability: OpenSearch Dashboard - Unauth Access
**Classification:** OPENSEARCH
**Source:** Nuclei Template (`opensearch-dashboard-unauth.yaml`)

## Description
OpenSearch Dashboard is a visualization and management tool for OpenSearch. This template detects instances that are accessible without authentication, potentially exposing sensitive data and system information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /app/home#/ HTTP/1.1
Host: {{Hostname}}
```

