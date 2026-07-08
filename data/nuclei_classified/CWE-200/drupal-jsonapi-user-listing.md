# Vulnerability: Drupal JSON:API Username Listing - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`drupal-jsonapi-user-listing.yaml`)

## Description
Drupal JSON:API username listing was detected via the /user/user endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/jsonapi/user/user
```

