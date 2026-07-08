# Vulnerability: Apache Kafka Connect UI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kafka-connect-ui.yaml`)

## Description
Apache Kafka Connect UI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

