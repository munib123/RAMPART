# Nuclei Template: Laravel Debug Info Leak
**Template ID:** laravel-debug-infoleak
**Vulnerability Class:** Information Exposure Through Debug Information
**Severity:** Medium
**CWE:** CWE-215
**Source:** Nuclei Template (`laravel-debug-infoleak.yaml`)

## Vulnerability Information & PoC

## Description
This template can be used to detect a Laravel debug information leak by making a POST-based request.

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/dem0ns/improper/blob/master/laravel/5_debug/1.png
