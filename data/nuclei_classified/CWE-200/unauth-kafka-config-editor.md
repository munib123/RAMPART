# Vulnerability: Kafka Config Editor - Unauthenticated Access
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-kafka-config-editor.yaml`)

## Description
Kafka Config Editor was detected and appeared to be accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

