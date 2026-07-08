# Vulnerability: Magento Debug Log - Exposure
**Classification:** CWE-538
**Source:** Nuclei Template (`magento-debug-log-exposure.yaml`)

## Description
Detected Magento debug.log file was publicly accessible. This file contained sensitive debugging information including full server paths, stack traces, customer activity, internal code paths, cache data, and cron job details.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/var/log/debug.log
```

