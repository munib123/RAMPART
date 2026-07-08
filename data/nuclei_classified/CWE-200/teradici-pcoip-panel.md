# Vulnerability: Teradici PCoIP Zero Client Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teradici-pcoip-panel.yaml`)

## Description
Teradici PCoIP Zero Client login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.html
```

