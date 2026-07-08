# Vulnerability: Serge Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`serge-panel.yaml`)

## Description
Serge is a web interface for chatting with Alpaca through llama.cpp. This template detects the presence of a Serge chat interface.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

