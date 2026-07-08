# Vulnerability: D-Link DNS Series  CGI Script - Unauthenticated
**Classification:** UNAUTH
**Source:** Nuclei Template (`dlink-unauth-cgi-script.yaml`)

## Description
A vulnerability has been identified in the D-Link DNS series network storage devices, allowing for the exposure of sensitive device information to unauthorized actors. This vulnerability is due to an unauthenticated access flaw in the info.cgi script, which can be exploited via a simple HTTP GET request, affecting over 920,000 devices on the Internet.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/info.cgi
```

