# Vulnerability: Drupal Directory Listing
**Classification:** DRUPAL
**Source:** Nuclei Template (`drupal-directory-listing.yaml`)

## Description
Detects enabled directory listing on Drupal installations that may expose sensitive files and directory structures.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/sites/
GET {{BaseURL}}/modules/
GET {{BaseURL}}/themes/
GET {{BaseURL}}/profiles/
GET {{BaseURL}}/includes/
GET {{BaseURL}}/misc/
GET {{BaseURL}}/scripts/
GET {{BaseURL}}/core/
GET {{BaseURL}}/vendor/
GET {{BaseURL}}/libraries/
```

