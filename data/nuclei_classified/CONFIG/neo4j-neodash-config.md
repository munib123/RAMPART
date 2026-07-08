# Vulnerability: Neo4j Neodash Config - Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`neo4j-neodash-config.yaml`)

## Description
Detects the file config.json from Neo4j Neodash web application, it contains information about DB connection with Neo4J.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.json
```

