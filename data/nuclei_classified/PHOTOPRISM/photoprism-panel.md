# Vulnerability: PhotoPrism Panel - Detect
**Classification:** PHOTOPRISM
**Source:** Nuclei Template (`photoprism-panel.yaml`)

## Description
PhotoPrism is an AI-powered photos app for the decentralized web. This template detects the presence of PhotoPrism login panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/library/login
```

