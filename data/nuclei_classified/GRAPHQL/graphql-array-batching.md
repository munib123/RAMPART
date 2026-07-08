# Vulnerability: GraphQL Array-based Batching
**Classification:** GRAPHQL
**Source:** Nuclei Template (`graphql-array-batching.yaml`)

## Description
Some GraphQL engines support batching of multiple queries into a single request. This allows users to request multiple objects or multiple instances of objects efficiently.
However, an attacker can leverage this feature to evade many security measures, including Rate Limit.

## Secure Mitigation
Deactivate or limit Batching in your GraphQL engine.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

[{"query":"query {\n __typename \n }"}, {"query":"mutation { \n __typename \n }"}]

POST /api/graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

[{"query":"query {\n __typename \n }"}, {"query":"mutation { \n __typename \n }"}]
```

