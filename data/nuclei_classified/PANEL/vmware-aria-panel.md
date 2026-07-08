# Vulnerability: VMware Aria Operations Login - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`vmware-aria-panel.yaml`)

## Description
Detects VMware Aria Operations Panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/login.action
```

