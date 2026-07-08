# Vulnerability: Kafka Manager Panel - Unauthorized Access
**Classification:** MISCONFIG
**Source:** Nuclei Template (`kafka-manager-unauth.yaml`)

## Description
A kafka manager unauthorized access was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

