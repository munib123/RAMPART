# Vulnerability: ChurchCRM - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`churchcrm-default-login.yaml`)

## Description
ChurchCRM contains a default login vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /session/begin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

User={{username}}&Password={{password}}
```

