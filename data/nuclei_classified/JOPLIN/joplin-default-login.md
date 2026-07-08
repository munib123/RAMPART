# Vulnerability: Joplin - Default Login
**Classification:** JOPLIN
**Source:** Nuclei Template (`joplin-default-login.yaml`)

## Description
Joplin Server installations are vulnerable to default administrative credentials. The system ships with a default admin account using the credentials admin@localhost:admin. Attackers can leverage these default credentials to gain administrative access to the Joplin Server instance, potentially compromising sensitive user data and system functionality.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/sessions HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "email": "{{username}}",
  "password": "{{password}}"
}
```

