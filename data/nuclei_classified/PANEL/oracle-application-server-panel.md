# Vulnerability: Oracle Application Server Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`oracle-application-server-panel.yaml`)

## Description
Oracle Application Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/em/console/ias/oc4j/home
GET {{BaseURL}}
```

