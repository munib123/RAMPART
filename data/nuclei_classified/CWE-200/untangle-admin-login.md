# Vulnerability: Untangle Administrator Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`untangle-admin-login.yaml`)

## Description
Untangle Administrator is a centralized web-based management console that allows administrators to efficiently configure, monitor, and control various network security and filtering features provided by the Untangle NG Firewall, ensuring robust network protection and policy enforcement.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/auth/login
```

