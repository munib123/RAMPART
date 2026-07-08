# Vulnerability: SillyTavern Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`sillytavern-panel.yaml`)

## Description
SillyTavern was detected. SillyTavern is a character-based AI roleplay and chat frontend that connects to local or remote LLM backends. Exposed instances may allow unauthenticated access to AI models and conversation history.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

