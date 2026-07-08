# Vulnerability: Zammad Helpdesk Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`zammad-helpdesk-panel.yaml`)

## Description
Zammad is an open source helpdesk and customer support system that provides ticket management, live chat, and knowledge base functionality. This template detects exposed Zammad installations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

