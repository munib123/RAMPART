# Nuclei Template: OpenLiteSpeed WebAdmin - Default Login
**Template ID:** openlitespeed-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`openlitespeed-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected OpenLiteSpeed WebAdmin Console was using default credentials.

## Steps to reproduce / Exploit Payload
```http
POST /login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userid={{username}}&pass={{password}}
```

## References
- https://www.digitalocean.com/community/tutorials/how-to-install-the-openlitespeed-web-server-on-ubuntu-18-04
