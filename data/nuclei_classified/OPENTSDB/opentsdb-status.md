# Vulnerability: OpenTSDB - Detect
**Classification:** OPENTSDB
**Source:** Nuclei Template (`opentsdb-status.yaml`)

## Description
OpenTSDB stats exposed which is commonly used in monitoring and observability scenarios where tracking and analyzing the performance of systems, applications, and infrastructure over time is essential.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/stats?json
```

