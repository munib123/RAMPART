# Vulnerability: PostHog Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`posthog-admin-panel.yaml`)

## Description
PostHog login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?next=/
```

