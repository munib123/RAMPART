# Nuclei Template: IDEMIA BIOMetrics - Default Login
**Template ID:** idemia-biometrics-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`idemia-biometrics-default-login.yaml`)

## Vulnerability Information & PoC

## Description
IDEMIA BIOMetrics application  default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /cgi-bin/login.cgi HTTP/1.1
Host: {{Hostname}}

password={{password}}
```

## References
- https://www.google.com/search?q=idemia+password%3D+"12345"
