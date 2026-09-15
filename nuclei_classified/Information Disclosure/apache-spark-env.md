# Nuclei Template: Apache Spark Environment - Exposure
**Template ID:** apache-spark-env
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`apache-spark-env.yaml`)

## Vulnerability Information & PoC

## Description
Detected Apache Spark Web UI exposed environment variables and application information without authentication, potentially revealing sensitive configuration details.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/v1/applications
GET {{BaseURL}}/environment/
```

## References
- https://spark.apache.org/docs/latest/monitoring.html
