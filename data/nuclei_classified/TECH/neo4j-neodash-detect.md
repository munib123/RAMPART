# Vulnerability: Neo4j Neodash - Detect
**Classification:** TECH
**Source:** Nuclei Template (`neo4j-neodash-detect.yaml`)

## Description
Detects a Neo4j Neodash web application, a Dashboard Builder for Neo4j.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

