# Vulnerability: Storybook Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`storybook-panel.yaml`)

## Description
Storybook panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/?path=/settings/about
```

