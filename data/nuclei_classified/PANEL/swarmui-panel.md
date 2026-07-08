# Vulnerability: SwarmUI Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`swarmui-panel.yaml`)

## Description
SwarmUI (formerly StableSwarmUI) is a modular Stable Diffusion web interface built on ASP.NET Core.
It provides a feature-rich UI for AI image generation

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/Login
```

