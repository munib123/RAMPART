# Vulnerability: Bitbucket Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`bitbucket-panel.yaml`)

## Description
Bitbucket panel was detected. Bitbucket is a Git-based source code repository hosting service owned by Atlassian, providing CI/CD and collaboration features.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
GET {{BaseURL}}
```

