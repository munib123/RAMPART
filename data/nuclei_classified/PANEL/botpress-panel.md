# Vulnerability: Botpress Admin Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`botpress-panel.yaml`)

## Description
Botpress admin panel was detected. Botpress is an open-source conversational AI platform for building chatbots and virtual assistants.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin
```

