# Vulnerability: Apache RocketMQ Console Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rocketmq-console-exposure.yaml`)

## Description
Apache RocketMQ Console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

