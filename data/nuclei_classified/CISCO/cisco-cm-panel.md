# Vulnerability: Cisco Unified CM Console - Panel
**Classification:** CISCO
**Source:** Nuclei Template (`cisco-cm-panel.yaml`)

## Description
Cisco Unified CM Console panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ccmadmin/showHome.do
```

