# Vulnerability: Dkron - Detect
**Classification:** TECH
**Source:** Nuclei Template (`dkron-detect.yaml`)

## Description
detected a Dkron server, a distributed and fault-tolerant job scheduling system for cloud-native environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/
```

