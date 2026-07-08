# Vulnerability: SysAid Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sysaid-panel.yaml`)

## Description
Detects the presence of a SysAid Help Desk Software login panel by identifying characteristic login pages, favicon hash, and system-specific content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.jsp
GET {{BaseURL}}/InvalidAccount.jsp
GET {{BaseURL}}/favicon.ico
```

