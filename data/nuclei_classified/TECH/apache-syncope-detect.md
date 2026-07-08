# Vulnerability: Apache Syncope - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-syncope-detect.yaml`)

## Description
Detected an Apache Syncope server, an enterprise digital identity management platform built with Java EE and licensed under Apache 2.0.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/syncope-enduser/
GET {{BaseURL}}/syncope-wa/
GET {{BaseURL}}/syncope-console/
```

