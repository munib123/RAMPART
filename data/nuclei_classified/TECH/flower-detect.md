# Vulnerability: Flower - Detect
**Classification:** TECH
**Source:** Nuclei Template (`flower-detect.yaml`)

## Description
Detected that Flower was a real-time monitor and web admin for the Celery distributed task queue.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

