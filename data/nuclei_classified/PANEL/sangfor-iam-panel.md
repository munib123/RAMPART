# Vulnerability: Sangfor Internet Access Management - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`sangfor-iam-panel.yaml`)

## Description
Sangfor Internet Access Management (IAM) is a network access control and web filtering appliance from Sangfor Technologies used for managing internet access policies and user authentication in enterprise environments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

