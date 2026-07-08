# Vulnerability: GraphQL Field Suggestion Information Disclosure
**Classification:** GRAPHQL
**Source:** Nuclei Template (`graphql-field-suggestion.yaml`)

## Description
If introspection is disabled on your target, Field Suggestion can allow users to still earn information on the GraphQL schema.
By default, GraphQL backends have a feature for fields and operations suggestions.
If you try to query a field but you have made a typo, GraphQL will attempt to suggest fields that are similar to the initial attempt.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"query {\n  __schema {\n directive\n }\n}","variables":null}

POST /api/graphql HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"query":"query {\n  __schema {\n directive\n }\n}","variables":null}
```

