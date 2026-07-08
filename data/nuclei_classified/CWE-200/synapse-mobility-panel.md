# Vulnerability: Synapse Mobility Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`synapse-mobility-panel.yaml`)

## Description
Synapse Mobility login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pureweb/server/login.jsp
```

