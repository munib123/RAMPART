# Vulnerability: Apache Shenyu Gateway Management System - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-shenyu-detect.yaml`)

## Description
Detects a Apache Shenyu Gateway Management System, a Java native API Gateway for service proxy, protocol conversion and API governance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

