# Vulnerability: Redis Configuration File - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`redis-config.yaml`)

## Description
Redis configuration file was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/redis.conf
```

