# Vulnerability: Mealie Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`mealie-panel.yaml`)

## Description
Detected Mealie was a self-hosted recipe manager and meal planner with a Vue/Nuxt frontend and FastAPI backend.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/api/app/about
```

