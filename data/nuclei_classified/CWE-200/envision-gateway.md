# Vulnerability: EnvisionGateway Scheduler Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`envision-gateway.yaml`)

## Description
EnvisionGateway scheduler panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#
```

