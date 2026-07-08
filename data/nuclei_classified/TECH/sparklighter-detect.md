# Vulnerability: Spark Lighter Detection
**Classification:** TECH
**Source:** Nuclei Template (`sparklighter-detect.yaml`)

## Description
Detects a Spark Lighter server, a REST API for Apache Spark on K8S or YARN.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lighter/api
```

