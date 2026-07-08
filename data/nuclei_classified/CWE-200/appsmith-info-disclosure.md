# Vulnerability: Appsmith <= v1.97 - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`appsmith-info-disclosure.yaml`)

## Description
Appsmith <= v1.97 instance management API endpoints are accessible without authentication, allowing an attacker to obtain sensitive information such as license plan, instance ID, authentication providers, feature flags, and configuration metadata via unauthenticated requests to specific API endpoints.

## Secure Mitigation
Restrict unauthenticated access to the management API endpoints and ensure that only authorized users can retrieve sensitive configuration information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1/consolidated-api/view
GET {{BaseURL}}/api/v1/users/features
GET {{BaseURL}}/api/v1/tenants/current
```

