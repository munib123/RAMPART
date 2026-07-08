# Vulnerability: WordPress Members Plugin - Debug/Error Log Disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-members-log-disclosure.yaml`)

## Description
The WordPress Members plugin exposes error/debug log files that may contain sensitive information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/debug.log
```

