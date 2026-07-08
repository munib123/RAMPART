# Vulnerability: Jamf Pro Setup Assistant Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`jamf-setup-assistant.yaml`)

## Description
Jamf Pro Setup Assistant panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setupAssistant.html
```

