# Nuclei Template: PostgreSQL Cluster - Configuration
**Template ID:** postgresql-cluster-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`postgresql-cluster-config.yaml`)

## Vulnerability Information & PoC

## Description
PostgreSQL Cluster Configuration Page was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config
```

