# Vulnerability: RedisInsight - Unauthenticated Access
**Classification:** REDIS
**Source:** Nuclei Template (`unauth-redis-insight.yaml`)

## Description
RedisInsight was able to be accessed because no authentication was required.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

