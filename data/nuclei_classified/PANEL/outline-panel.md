# Vulnerability: Outline Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`outline-panel.yaml`)

## Description
Outline (getoutline.com / github.com/outline/outline) is a popular open-source team knowledge base / wiki, often self-hosted as a Notion alternative. Exposed self-hosted instances may reveal team documents and provide a path to login enumeration if SSO is misconfigured.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

