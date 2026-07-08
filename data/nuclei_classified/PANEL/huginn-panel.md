# Vulnerability: Huginn Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`huginn-panel.yaml`)

## Description
Huginn products was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/users/sign_in
```

