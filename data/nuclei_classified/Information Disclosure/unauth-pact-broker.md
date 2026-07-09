# Nuclei Template: Unauth Pact Broker - Detect
**Template ID:** unauth-pact-broker
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-pactbroker.yaml`)

## Vulnerability Information & PoC

## Description
Unauthenticated access to Pact Broker, a repository for consumer-driven contracts and verification results.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/pacts
GET {{BaseURL}}/ui/relationships
```

## References
- https://docs.pact.io/pact_broker
- https://github.com/pact-foundation/pact_broker
