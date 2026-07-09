# Nuclei Template: Magento Debug Log - Exposure
**Template ID:** magento-debug-log-exposure
**Vulnerability Class:** File and Directory Information Exposure
**Severity:** Medium
**CWE:** CWE-538
**Source:** Nuclei Template (`magento-debug-log-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected Magento debug.log file was publicly accessible. This file contained sensitive debugging information including full server paths, stack traces, customer activity, internal code paths, cache data, and cron job details.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/var/log/debug.log
```

## References
- https://devdocs.magento.com/guides/v2.4/config-guide/log/log-intro.html
