# Vulnerability: PostgreSQL Cluster - Configuration
**Classification:** CWE-200
**Source:** Nuclei Template (`postgresql-cluster-config.yaml`)

## Description
PostgreSQL Cluster Configuration Page was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config
```

