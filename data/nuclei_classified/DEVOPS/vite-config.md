# Vulnerability: Vite Configuration - File Exposure
**Classification:** DEVOPS
**Source:** Nuclei Template (`vite-config.yaml`)

## Description
The vite.config.js file is used to customize the behavior of Vite and specify various settings for your project.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vite.config.js
```

