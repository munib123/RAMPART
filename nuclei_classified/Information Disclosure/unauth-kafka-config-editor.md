# Nuclei Template: Kafka Config Editor - Unauthenticated Access
**Template ID:** unauth-kafka-config-editor
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`unauth-kafka-config-editor.yaml`)

## Vulnerability Information & PoC

## Description
Kafka Config Editor was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

