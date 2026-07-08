# Vulnerability: Atlassian Bamboo Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`atlassian-bamboo-panel.yaml`)

## Description
Atlassian Bamboo login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/userlogin!doDefault.action?os_destination=%2Fstart.action
```

