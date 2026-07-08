# Vulnerability: Zen Cart Log File Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`zen-cart-log-exposure.yaml`)

## Description
Detected exposed Zen Cart log files that may contain sensitive information including error messages, file paths, database queries, and customer data.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/logs/
GET {{BaseURL}}/cache/
GET {{BaseURL}}/includes/logs/
GET {{BaseURL}}/admin/logs/
```

