# Vulnerability: Docker Registry Browser - Detect
**Classification:** DOCKER
**Source:** Nuclei Template (`docker-registry-browser-detect.yaml`)

## Description
Detected the presence of Docker Registry Browser technology based on known paths and characteristic content in the HTTP response.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

