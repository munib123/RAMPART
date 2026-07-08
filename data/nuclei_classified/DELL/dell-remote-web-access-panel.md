# Vulnerability: Dell Remote Web Access Panel - Detect
**Classification:** DELL
**Source:** Nuclei Template (`dell-remote-web-access-panel.yaml`)

## Description
Dell Remote Web Access is a secure web portal that enables remote access to files, applications, and desktops hosted on Dell servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

