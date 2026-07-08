# Vulnerability: Kafka Operation API - Cluster
**Classification:** CWE-200
**Source:** Nuclei Template (`kafka-api-cluster.yaml`)

## Description
Kafka Operation API Cluster page was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kafka/clusters
```

