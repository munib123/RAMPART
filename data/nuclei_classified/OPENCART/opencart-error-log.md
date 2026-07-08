# Vulnerability: OpenCart Error Log Disclosure
**Classification:** OPENCART
**Source:** Nuclei Template (`opencart-error-log.yaml`)

## Description
Detected exposed OpenCart error log files that may contain sensitive information
including file paths, database errors, PHP warnings, and internal application details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/system/storage/logs/error.log
GET {{BaseURL}}/opencart/system/storage/logs/error.log
GET {{BaseURL}}/storage/logs/error.log
GET {{BaseURL}}/error.log
GET {{BaseURL}}/system/logs/error.log
```

