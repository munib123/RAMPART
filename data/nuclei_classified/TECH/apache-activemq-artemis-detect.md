# Vulnerability: Apache ActiveMQ Artemis - Detection
**Classification:** TECH
**Source:** Nuclei Template (`apache-activemq-artemis-detect.yaml`)

## Description
Detects a Apache ActiveMQ Artemis Console, the next generation message broker by ActiveMQ.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console/hawtconfig.json
```

