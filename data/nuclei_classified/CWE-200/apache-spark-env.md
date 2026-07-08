# Vulnerability: Apache Spark Environment - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`apache-spark-env.yaml`)

## Description
Detected Apache Spark Web UI exposed environment variables and application information without authentication, potentially revealing sensitive configuration details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/applications
GET {{BaseURL}}/environment/
```

