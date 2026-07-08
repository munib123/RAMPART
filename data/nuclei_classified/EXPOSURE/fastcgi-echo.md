# Vulnerability: FastCGI Echo Endpoint Script - Detect
**Classification:** EXPOSURE
**Source:** Nuclei Template (`fastcgi-echo.yaml`)

## Description
FastCGI echo endpoint script was detected, which lists several kinds of sensitive information such as port numbers, server software versions, port numbers, and IP addresses.

## Secure Mitigation
Remove or disable FastCGI module delivered with the Apache httpd server which is incorporated into the Oracle Application Server.FastCGI echo programs (echo and echo2).

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/fcgi-bin/echo
```

