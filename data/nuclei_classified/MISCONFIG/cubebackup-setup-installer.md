# Vulnerability: CubeBackup Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`cubebackup-setup-installer.yaml`)

## Description
Detects exposed CubeBackup Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

