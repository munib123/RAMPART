# Vulnerability: Apache Pinot - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-pinot-detect.yaml`)

## Description
Detects a Apache Pinot web application, A realtime distributed OLAP datastore.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

