# Vulnerability: Laravel Debug Enabled
**Classification:** DEBUG
**Source:** Nuclei Template (`laravel-debug-enabled.yaml`)

## Description
Laravel with APP_DEBUG set to true is prone to show verbose errors.

## Secure Mitigation
Disable Laravel's debug mode by setting APP_DEBUG to false.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_ignition/health-check
```

