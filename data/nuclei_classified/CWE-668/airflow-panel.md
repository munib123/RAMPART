# Vulnerability: Apache Airflow Admin Login Panel
**Classification:** CWE-668
**Source:** Nuclei Template (`airflow-panel.yaml`)

## Description
An Apache Airflow admin login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/
GET {{BaseURL}}/admin/airflow/login
```

