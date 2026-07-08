# Vulnerability: Airflow Debug Trace
**Classification:** APACHE
**Source:** Nuclei Template (`airflow-debug.yaml`)

## Description
Airflow Debug Trace enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/airflow/login
```

