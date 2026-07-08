# Vulnerability: Apache Allura - Detection
**Classification:** TECH
**Source:** Nuclei Template (`apache-allura-detect.yaml`)

## Description
Detects a Apache Allura server, a open source implementation of a software "forge".

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/neighborhood
```

