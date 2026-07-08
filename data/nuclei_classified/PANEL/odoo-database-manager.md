# Vulnerability: Odoo - Database Manager Discovery
**Classification:** PANEL
**Source:** Nuclei Template (`odoo-database-manager.yaml`)

## Description
Odoo database manager was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/database/manager
```

