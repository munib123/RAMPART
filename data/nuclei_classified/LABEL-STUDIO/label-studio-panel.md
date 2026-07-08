# Vulnerability: Label Studio - Login Panel
**Classification:** LABEL-STUDIO
**Source:** Nuclei Template (`label-studio-panel.yaml`)

## Description
Detects the presence of the Label Studio Login Page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /user/login HTTP/1.1
Host: {{Hostname}}
```

