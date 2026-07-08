# Vulnerability: Milesight Industrial Cellular Routers - Information Disclosure
**Classification:** MILESIGHT
**Source:** Nuclei Template (`milesight-system-log.yaml`)

## Description
A critical security vulnerability has been identified in Milesight Industrial Cellular Routers, compromising the security discovered that it was publicly disclosing system logs, which included internal information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/lang/log/system.log
```

