# Vulnerability: WildFly Welcome Page - Tech Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wildfly-panel.yaml`)

## Description
WildFly welcome page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

