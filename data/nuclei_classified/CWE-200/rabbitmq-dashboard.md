# Vulnerability: RabbitMQ Management Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rabbitmq-dashboard.yaml`)

## Description
RabbitMQ Management panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

