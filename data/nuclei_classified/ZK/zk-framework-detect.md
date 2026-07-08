# Vulnerability: ZK Framework - Detect
**Classification:** ZK
**Source:** Nuclei Template (`zk-framework-detect.yaml`)

## Description
Detects the presence of ZK JavaFramework and attempts to extract its version.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

