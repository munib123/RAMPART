# Vulnerability: OneDev Panel - Detect
**Classification:** TECH
**Source:** Nuclei Template (`onedev-panel.yaml`)

## Description
OneDev is a Git Server with CI/CD, Kanban, and Packages.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/~login
```

