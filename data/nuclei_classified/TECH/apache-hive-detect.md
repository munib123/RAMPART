# Vulnerability: Apache Hive - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-hive-detect.yaml`)

## Description
Apache Hive web application was detected, a data warehouse software facilitates reading, writing, and managing large datasets residing in distributed storage using SQL.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

