# Vulnerability: Nocobase - Config
**Classification:** NOCOBASE
**Source:** Nuclei Template (`nocobase-config.yaml`)

## Description
The path /api/v1/db/meta/nocodb/info of the NocoBase web application was exposed, revealing internal information. NocoBase was an extensibility-first, open-source no-code/low-code platform for building business applications and enterprise solutions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v1/db/meta/nocodb/info HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

