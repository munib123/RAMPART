# Vulnerability: Apache InLong - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-inlong-detect.yaml`)

## Description
Detects a Apache InLong server, a one-stop, full-scenario integration framework for massive data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

