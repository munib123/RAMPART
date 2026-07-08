# Vulnerability: MailHog Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mailhog-panel.yaml`)

## Description
MailHog panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

