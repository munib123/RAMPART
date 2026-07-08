# Vulnerability: RabbitMQ Exporter
**Classification:** RABBITMQ
**Source:** Nuclei Template (`rabbitmq-exporter-metrics.yaml`)

## Description
RabbitMQ Exporter is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
```

