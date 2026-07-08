# Vulnerability: Apache Gravitino - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-gravitino-detect.yaml`)

## Description
Detects a Apache Gravitino web application, world's most powerful open data catalog for building a high-performance, geo-distributed and federated metadata lake.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/metalakes
```

