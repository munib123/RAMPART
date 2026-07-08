# Vulnerability: Szhe Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`szhe-default-login.yaml`)

## Description
Szhe default login information was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

email={{username}}&password={{password}}&remeber=true
```

