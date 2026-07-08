# Vulnerability: Wpdm-Cache Session
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wpdm-cache-session.yaml`)

## Description
Leaked session of Wpdm Cache wordpress plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/uploads/wpdm-cache/
```

