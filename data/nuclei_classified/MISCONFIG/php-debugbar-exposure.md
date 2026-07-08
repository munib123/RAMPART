# Vulnerability: Php Debug Bar - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`php-debugbar-exposure.yaml`)

## Description
The DebugBar integrates easily into projects and can display profiling data from any part of your application.This template detects exposed PHP Debug Bars by looking for known response bodies and the `phpdebugbar-id` in headers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/_debugbar/open
```

