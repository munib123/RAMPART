# Vulnerability: Apache Kyuubi - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-kyuubi-detect.yaml`)

## Description
Detects a Apache Kyuubi server, a distributed and multi-tenant gateway to provide serverless SQL on data warehouses and lakehouses.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/
```

