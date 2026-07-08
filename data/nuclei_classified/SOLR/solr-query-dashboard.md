# Vulnerability: Solr - Admin Page Access
**Classification:** SOLR
**Source:** Nuclei Template (`solr-query-dashboard.yaml`)

## Description
Solr's admin page was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/
GET {{BaseURL}}/solr/admin/
```

