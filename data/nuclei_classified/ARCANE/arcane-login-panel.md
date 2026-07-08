# Vulnerability: Arcane Login Panel - Detect
**Classification:** ARCANE
**Source:** Nuclei Template (`arcane-login-panel.yaml`)

## Description
Detects the presence of the Arcane login panel, a modern Docker management platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/login
```

