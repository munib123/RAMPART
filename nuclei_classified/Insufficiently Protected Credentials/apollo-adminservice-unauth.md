# Nuclei Template: Apollo Admin Service - Unauthenticated Access
**Template ID:** apollo-adminservice-unauth
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`apollo-adminservice-unauth.yaml`)

## Vulnerability Information & PoC

## Description
ApolloAdminservice was able to be accessed without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/apps
```

## References
- https://landgrey.me/blog/20/
