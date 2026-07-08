# Vulnerability: JBoss SOA Platform Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jboss-soa-platform.yaml`)

## Description
JBoss SOA Platform login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/css/footer.js
GET {{BaseURL}}
```

