# Vulnerability: Linkwarden Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`linkwarden-panel.yaml`)

## Description
Linkwarden (linkwarden.app / github.com/linkwarden/linkwarden) is a popular open-source self-hosted bookmark and link archiving manager. Default Docker port 3000. Exposed instances may reveal users' archived link collections, screenshots, and PDFs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

