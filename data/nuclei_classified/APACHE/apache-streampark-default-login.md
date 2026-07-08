# Vulnerability: Apache Streampark - Default Login
**Classification:** APACHE
**Source:** Nuclei Template (`apache-streampark-default-login.yaml`)

## Description
Apache Streampark server enables default admin credentials. An attacker can execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /passport/signin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8

password={{password}}&username={{username}}&loginType=PASSWORD
```

