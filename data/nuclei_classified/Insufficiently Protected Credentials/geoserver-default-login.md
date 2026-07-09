# Nuclei Template: Geoserver Admin - Default Login
**Template ID:** geoserver-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`geoserver-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Geoserver default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /geoserver/j_spring_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}

GET /geoserver/web/ HTTP/1.1
Host: {{Hostname}}
```

## References
- http://geoserver.org/
