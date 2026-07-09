# Nuclei Template: Drupal JSON:API Username Listing - Detect
**Template ID:** drupal-jsonapi-user-listing
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`drupal-jsonapi-user-listing.yaml`)

## Vulnerability Information & PoC

## Description
Drupal JSON:API username listing was detected via the /user/user endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/jsonapi/user/user
```

## References
- https://www.drupal.org/project/drupal/issues/3240913
