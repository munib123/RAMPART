# Nuclei Template: Zen Cart Log File Exposure
**Template ID:** zen-cart-log-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`zen-cart-log-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Detected exposed Zen Cart log files that may contain sensitive information including error messages, file paths, database queries, and customer data.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/logs/
GET {{BaseURL}}/cache/
GET {{BaseURL}}/includes/logs/
GET {{BaseURL}}/admin/logs/
```

## References
- https://www.zen-cart.com/
- https://docs.zen-cart.com/user/troubleshooting/debug_logs/
