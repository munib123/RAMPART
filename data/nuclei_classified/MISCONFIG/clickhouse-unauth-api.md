# Vulnerability: ClickHouse API Database Interface - Improper Authorization
**Classification:** MISCONFIG
**Source:** Nuclei Template (`clickhouse-unauth-api.yaml`)

## Description
Clickhouse API Database is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?query=SHOW%20DATABASES
```

