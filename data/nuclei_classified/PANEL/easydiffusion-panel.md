# Vulnerability: Easy Diffusion Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`easydiffusion-panel.yaml`)

## Description
Easy Diffusion (formerly Stable Diffusion UI) was detected. Easy Diffusion is a one-click, self-hosted Stable Diffusion web application focused on accessibility and ease of use for AI image generation. Exposed instances allow unauthenticated access to image generation capabilities and stored outputs.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

