# Nuclei Template: Redis Configuration File - Detect
**Template ID:** redis-config
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`redis-config.yaml`)

## Vulnerability Information & PoC

## Description
Redis configuration file was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/redis.conf
```

## References
- https://redis.io/docs/manual/config/
