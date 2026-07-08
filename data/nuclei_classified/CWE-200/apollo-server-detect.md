# Vulnerability: Apollo Server GraphQL Introspection - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apollo-server-detect.yaml`)

## Description
Apollo Server GraphQL introspection was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/graphql
```

