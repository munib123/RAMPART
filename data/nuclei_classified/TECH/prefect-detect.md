# Vulnerability: Prefect - Detect
**Classification:** TECH
**Source:** Nuclei Template (`prefect-detect.yaml`)

## Description
Detected Prefect, a modern workflow orchestration platform with Orion UI for managing data pipelines.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

