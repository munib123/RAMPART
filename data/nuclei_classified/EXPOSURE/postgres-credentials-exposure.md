# Vulnerability: PostgreSQL Credentials - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`postgres-credentials-exposure.yaml`)

## Description
Detects the exposure of PostgreSQL credentials and history files (.pgpass) via HTTP. These files may contain plaintext database usernames and passwords, and their leakage could allow unauthorized access to sensitive databases or internal infrastructure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.pgpass
```

