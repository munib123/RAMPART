# Vulnerability: OpenNebula Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opennebula-panel.yaml`)

## Description
OpenNebula login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

