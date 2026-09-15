# Nuclei Template: Kafka Operation API - Cluster
**Template ID:** kafka-api-cluster
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`kafka-api-cluster.yaml`)

## Vulnerability Information & PoC

## Description
Kafka Operation API Cluster page was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/kafka/clusters
```

