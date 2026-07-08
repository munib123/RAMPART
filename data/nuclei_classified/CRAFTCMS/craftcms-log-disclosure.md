# Vulnerability: Craft CMS - Log File Disclosure
**Classification:** CRAFTCMS
**Source:** Nuclei Template (`craftcms-log-disclosure.yaml`)

## Description
Detected exposed Craft CMS log files due to misconfiguration, allowing unauthenticated access to sensitive information including error messages, stack traces, database queries, and potentially credentials or session data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/storage/logs/web.log
```

