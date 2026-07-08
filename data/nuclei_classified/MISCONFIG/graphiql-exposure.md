# Vulnerability: GraphiQL - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`graphiql-exposure.yaml`)

## Description
Detected publicly exposed GraphiQL consoles.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/graphiql
GET {{BaseURL}}/graphql
GET {{BaseURL}}/api/graphql
GET {{BaseURL}}/v1/graphql
GET {{BaseURL}}/query
GET {{BaseURL}}
```

