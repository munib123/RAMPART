# Vulnerability: HiveQueue Agent
**Classification:** MISCONFIG
**Source:** Nuclei Template (`hivequeue-agent.yaml`)

## Description
HiveQueue Agent is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/monitoring
```

