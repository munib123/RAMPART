# Vulnerability: Chroma DB - Information Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`chroma-db-unauth.yaml`)

## Description
Chroma DB API endpoints were accessible and exposed collection metadata, enabling enumeration of collections under the default tenant and database, potentially leading to sensitive vector data disclosure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/collections?tenant=default_tenant&database=default_database
GET {{BaseURL}}/api/v2/tenants/default_tenant/databases/default_database/collections
```

