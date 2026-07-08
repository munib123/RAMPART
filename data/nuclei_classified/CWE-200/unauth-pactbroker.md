# Vulnerability: Unauth Pact Broker - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-pactbroker.yaml`)

## Description
Unauthenticated access to Pact Broker, a repository for consumer-driven contracts and verification results.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/pacts
GET {{BaseURL}}/ui/relationships
```

