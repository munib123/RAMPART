# Vulnerability: Laravel Debug Info Leak
**Classification:** CWE-215
**Source:** Nuclei Template (`laravel-debug-infoleak.yaml`)

## Description
This template can be used to detect a Laravel debug information leak by making a POST-based request.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
```

