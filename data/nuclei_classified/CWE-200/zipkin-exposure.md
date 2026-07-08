# Vulnerability: Zipkin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`zipkin-exposure.yaml`)

## Description
Zipkin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/zipkin/
```

