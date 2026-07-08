# Vulnerability: Apache Hertzbeat - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-hertzbeat-detect.yaml`)

## Description
Detects a Apache Hertzbeat web application is in use, that is a real-time monitoring system with agentless, performance cluster, prometheus-compatible, custom monitoring and status page building capabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/assets/app-data.json
```

