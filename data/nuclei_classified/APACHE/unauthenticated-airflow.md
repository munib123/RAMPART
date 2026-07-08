# Vulnerability: Unauthenticated Airflow Instance
**Classification:** APACHE
**Source:** Nuclei Template (`unauthenticated-airflow.yaml`)

## Description
Airflow Instance is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/admin/
```

