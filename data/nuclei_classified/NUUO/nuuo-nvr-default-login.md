# Vulnerability: NUUO NVR - Default Login
**Classification:** NUUO
**Source:** Nuclei Template (`nuuo-nvr-default-login.yaml`)

## Description
NUUO NVR systems are often deployed with default credentials (admin:admin).This template detects systems using these default credentials.

## Vulnerable Code Pattern / Exploit Payload
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

