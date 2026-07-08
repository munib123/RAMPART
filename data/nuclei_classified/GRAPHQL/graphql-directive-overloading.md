# Vulnerability: GraphQL Directive Overloading
**Classification:** GRAPHQL
**Source:** Nuclei Template (`graphql-directive-overloading.yaml`)

## Description
GraphQL directive overloading occurs when multiple duplicated directives are allowed in a single query, potentially leading to denial of service attacks or resource exhaustion.

## Secure Mitigation
Configure GraphQL server to limit or prevent directive overloading by implementing proper validation and rate limiting.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query": "query cop { __typename @aa@aa@aa@aa@aa@aa@aa@aa@aa@aa }", "operationName": "cop"}
```

