# Vulnerability: Typebot Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`typebot-panel.yaml`)

## Description
Typebot is an open-source chatbot builder that allows you to create advanced
chatbots visually.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

