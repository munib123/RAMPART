# Vulnerability: Varnish Unauthenticated Cache Purge
**Classification:** MISCONFIG
**Source:** Nuclei Template (`unauthenticated-varnish-cache-purge.yaml`)

## Description
As per guideline one should protect purges with ACLs from unauthorized hosts.

## Vulnerable Code Pattern / Exploit Payload
```http
PURGE {{BaseURL}}
```

