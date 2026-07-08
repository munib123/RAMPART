# Vulnerability: Mattermost Login - Panel
**Classification:** LOGIN
**Source:** Nuclei Template (`mattermost-panel.yaml`)

## Description
Mattermost Login Panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

