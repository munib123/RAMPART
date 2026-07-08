# Vulnerability: GraphQL Alias-based Batching
**Classification:** GRAPHQL
**Source:** Nuclei Template (`graphql-alias-batching.yaml`)

## Description
GraphQL supports aliasing of multiple sub-queries into a single queries. This allows users to request multiple objects or multiple instances of objects efficiently.
However, an attacker can leverage this feature to evade many security measures, including rate limit.

## Secure Mitigation
Limit queries aliasing in your GraphQL Engine to ensure mitigation of aliasing-based attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"query {\n {{str}}1:__typename \n {{str}}2:__typename \n {{str}}3:__typename \n {{str}}4:__typename \n {{str}}5:__typename \n {{str}}6:__typename \n }"}

POST /api/graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"query {\n {{str}}1:__typename \n {{str}}2:__typename \n {{str}}3:__typename \n {{str}}4:__typename \n {{str}}5:__typename \n {{str}}6:__typename \n }"}
```

