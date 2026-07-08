# Vulnerability: Laravel Ignition - Log Viewer Information Disclosure
**Classification:** LARAVEL
**Source:** Nuclei Template (`laravel-ignition-log-viewer.yaml`)

## Description
Laravel Ignition's log viewer endpoint is publicly accessible and exposes application logs. These logs may contain stack traces, SQL queries, environment variables, API keys, user data, and other sensitive information.

## Secure Mitigation
Disable Ignition in production by setting APP_DEBUG=false. If Ignition must remain enabled, configure it to disable the log viewer endpoint via the ignition config file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_ignition/logs
```

