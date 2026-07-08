# Vulnerability: Apache Airflow Configuration Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`airflow-configuration-exposure.yaml`)

## Description
Apache Airflow configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/airflow.cfg
```

