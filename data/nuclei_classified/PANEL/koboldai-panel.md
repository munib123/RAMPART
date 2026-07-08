# Vulnerability: KoboldAI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`koboldai-panel.yaml`)

## Description
KoboldAI was detected. KoboldAI was an AI text adventure and story generation interface that supports multiple local and remote language models including koboldcpp and AI Horde.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

