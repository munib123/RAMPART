# Vulnerability: SafeNet Authentication Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`safenet-authentication-panel.yaml`)

## Description
SafeNet Authentication Service Self Enrollment login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/selfenrollment/Enrollment.aspx
```

