# Vulnerability: Apache Spark Application UI - Exposed
**Classification:** SPARK
**Source:** Nuclei Template (`apachespark-ui-exposed.yaml`)

## Description
Detects exposed PySparkShell Application UI by Apache Spark on port 4040. The UI should not be exposed to the internet as it may leak sensitive job and cluster information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jobs/
GET {{BaseURL}}:4040/jobs/
```

