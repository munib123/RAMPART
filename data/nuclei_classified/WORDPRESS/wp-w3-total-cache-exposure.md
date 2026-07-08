# Vulnerability: WordPress W3 Total Cache - Cache Files Exposure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-w3-total-cache-exposure.yaml`)

## Description
Detects publicly accessible W3 Total Cache database cache files in the wp-content/w3tc/dbcache/ directory. When database caching to disk is enabled, these files contain raw SQL query results, potentially exposing sensitive data such as user details, password hashes, emails, or other database content if the directory is not properly protected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/w3tc/dbcache/
```

