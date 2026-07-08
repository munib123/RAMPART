# Vulnerability: Apache Streampark - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-streampark-detect.yaml`)

## Description
Detects a Apache Streampark server, a easy-to-use streaming application development framework and operation platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

