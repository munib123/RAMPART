# Vulnerability: myLittleAdmin Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mylittleadmin-panel.yaml`)

## Description
myLittleAdmin login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/mylittleadmin/
```

