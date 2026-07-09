# Nuclei Template: Appsmith <= v1.97 - Information Disclosure
**Template ID:** appsmith-info-disclosure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`appsmith-info-disclosure.yaml`)

## Vulnerability Information & PoC

## Description
Appsmith <= v1.97 instance management API endpoints are accessible without authentication, allowing an attacker to obtain sensitive information such as license plan, instance ID, authentication providers, feature flags, and configuration metadata via unauthenticated requests to specific API endpoints.

## Impact
Attackers can extract detailed information about Appsmith enterprise features, authentication methods, and configuration, enabling more focused and effective attacks against the instance and its users.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/v1/consolidated-api/view
GET {{BaseURL}}/api/v1/users/features
GET {{BaseURL}}/api/v1/tenants/current
```

## Remediation
Restrict unauthenticated access to the management API endpoints and ensure that only authorized users can retrieve sensitive configuration information.

## References
- https://github.com/appsmithorg/appsmith/security/advisories/GHSA-qvvc-prjx-f85j
