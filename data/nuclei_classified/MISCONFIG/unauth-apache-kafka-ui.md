# Vulnerability: Apache Kafka - Unauthorized UI Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauth-apache-kafka-ui.yaml`)

## Description
Unauthorized access to apache kakfa UI.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ui/clusters/kafka-ui/brokers
```

