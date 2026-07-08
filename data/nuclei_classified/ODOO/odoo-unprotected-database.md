# Vulnerability: Odoo - Unprotected Database
**Classification:** ODOO
**Source:** Nuclei Template (`odoo-unprotected-database.yaml`)

## Description
The system has an Odoo application whose database manager is unprotected, indicating potential unauthorized access.

## Secure Mitigation
Implement and enforce proper authentication and access control measures to protect the Odoo database manager.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/web/database/manager
```

