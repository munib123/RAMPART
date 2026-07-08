# Vulnerability: Memos Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`memos-panel.yaml`)

## Description
Memos is a privacy-first, lightweight note-taking service

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/explore
```

