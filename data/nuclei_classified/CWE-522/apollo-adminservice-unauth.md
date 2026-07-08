# Vulnerability: Apollo Admin Service - Unauthenticated Access
**Classification:** CWE-522
**Source:** Nuclei Template (`apollo-adminservice-unauth.yaml`)

## Description
ApolloAdminservice was able to be accessed without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apps
```

