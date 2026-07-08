# Vulnerability: Odoo OpenERP Database Selector Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openerp-database.yaml`)

## Description
Odoo OpenERP database selector panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/database/selector/
```

