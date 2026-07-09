# Nuclei Template: Network Technologies Inc ENVIROMUX - Default Login
**Template ID:** enviromuux-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`enviromuux-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The ENVIROMUX environment monitoring system from Network Technologies Inc was found to be using its default login credentials. This default configuration could have allowed unauthorized users to gain access to the web management interface without authentication, potentially leading to information disclosure or unauthorized control over environmental monitoring systems.

## Steps to reproduce / Exploit Payload
```http
POST /goform/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

## References
- http://www.networktechinc.com/download/d-environment-monitor-16.html
- http://www.networktechinc.com/pdf/man154.pdf
