# Vulnerability: GraphQL Voyager - Exposed
**Classification:** MISCONFIG
**Source:** Nuclei Template (`graphql-voyager.yaml`)

## Description
GraphQL Voyager UI exposed (often a dev tool) which visualizes the GraphQL schema in production.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/voyager
GET {{BaseURL}}/voyager/
GET {{BaseURL}}/ui/voyager
GET {{BaseURL}}/graphql/voyager
```

