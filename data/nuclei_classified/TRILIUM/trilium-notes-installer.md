# Vulnerability: Trilium Notes Installer - Exposure
**Classification:** TRILIUM
**Source:** Nuclei Template (`trilium-notes-installer.yaml`)

## Description
Detects if the Trilium Notes setup page is accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup
```

