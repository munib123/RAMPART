# Vulnerability: Geoserver Admin - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`geoserver-default-login.yaml`)

## Description
Geoserver default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /geoserver/j_spring_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}

GET /geoserver/web/ HTTP/1.1
Host: {{Hostname}}
```

