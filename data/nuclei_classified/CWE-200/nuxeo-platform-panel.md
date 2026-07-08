# Vulnerability: Nuxeo Platform Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nuxeo-platform-panel.yaml`)

## Description
Nuxeo Platform login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nuxeo/login.jsp
```

