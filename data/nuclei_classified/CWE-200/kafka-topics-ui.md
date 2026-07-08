# Vulnerability: Apache Kafka Topics Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kafka-topics-ui.yaml`)

## Description
Apache Kafka Topics panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/info
```

