# Vulnerability: Apache Ozone - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-ozone-detect.yaml`)

## Description
Detects a Apache Ozone web application, a scalable, redundant, and distributed object store for Hadoop and Cloud-native environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/static/
```

