# Vulnerability: Apache Airflow v3 Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`airflow-v3-default-login.yaml`)

## Description
Apache Airflow v3 default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
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

