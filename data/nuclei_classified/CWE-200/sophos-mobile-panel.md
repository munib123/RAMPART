# Vulnerability: Sophos Mobile Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sophos-mobile-panel.yaml`)

## Description
Sophos Mobile panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.xhtml?faces-redirect=true
```

